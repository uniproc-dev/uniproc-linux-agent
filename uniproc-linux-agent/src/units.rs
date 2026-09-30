use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures::channel::oneshot;
use uniproc_agent_kit::monitor::{self, Collector, Monitor, Waker, Why};
use uniproc_agent_kit::{Board, Busy, Following, Latest, Runner, Tagged, Watch, board};
use uniproc_protocol::linux_capnp::{UnitActiveState, UnitFileState, UnitJob, UnitLoadState};
use zbus::DBusError;
use zbus::blocking::{Connection, MessageIterator};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

use crate::feed::Feed;
use crate::model::Key;

const DESTINATION: &str = "org.freedesktop.systemd1";
const MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const UNIT_PATHS: &str = "/org/freedesktop/systemd1/unit/";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const SERVICE: &str = "org.freedesktop.systemd1.Service";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";

const SPACING: Duration = Duration::from_millis(200);
const RECONNECT: Duration = Duration::from_secs(10);
const RESOLVE_RETRY: Duration = Duration::from_millis(100);
const RESOLVE_ATTEMPTS: u32 = 10;
const IDLE: Duration = Duration::from_secs(3600);
const JOB_WORKERS: usize = 2;

/// One unit of the system manager, as getUnits lists it.
#[derive(Clone, Debug, PartialEq)]
pub struct Unit {
    pub name: String,
    pub description: String,
    pub load: UnitLoadState,
    pub active: UnitActiveState,
    pub sub: String,
    pub file_state: UnitFileState,
    pub file: String,
    pub main: Option<Key>,
    pub job: UnitJob,
}

/// What watchUnit tells about one unit.
#[derive(Clone, Debug, PartialEq)]
pub struct UnitStatus {
    pub load: UnitLoadState,
    pub active: UnitActiveState,
    pub sub: String,
    pub main: Option<Key>,
    pub job: UnitJob,
    pub result: String,
    pub exec_main_code: u32,
    pub exec_main_status: i32,
    pub restarts: u32,
}

/// The units systemd has, the units someone follows, and the jobs asked of it.
#[derive(Clone)]
pub struct Units {
    pub latest: Latest<Vec<Unit>>,
    following: Following<String, UnitStatus>,
    runner: Runner<String>,
    bus: Bus,
}

impl Units {
    /// The current list and its tag; nothing ever fails it.
    pub fn list(&self) -> Tagged<Arc<Vec<Unit>>> {
        self.latest.get().unwrap_or_else(|_| Tagged {
            etag: 0,
            value: Arc::default(),
        })
    }

    pub fn watch(&self, name: String) -> Watch<UnitStatus> {
        self.following.watch(name)
    }

    /// Queues a job through the manager's `method`: StartUnit, StopUnit, RestartUnit or ReloadUnit.
    pub fn command(&self, name: String, method: &'static str) -> Result<oneshot::Receiver<u32>, Busy> {
        let bus = self.bus.clone();
        self.runner.run(name.clone(), move || {
            let Some(conn) = bus.get() else {
                return libc::ENOTCONN as u32;
            };
            match conn.call_method(Some(DESTINATION), MANAGER_PATH, Some(MANAGER), method, &(name.as_str(), "replace")) {
                Ok(_) => 0,
                Err(e) => errno(&e),
            }
        })
    }
}

#[derive(Clone, Default)]
struct Bus(Arc<Mutex<Option<Connection>>>);

impl Bus {
    fn get(&self) -> Option<Connection> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn set(&self, conn: Option<Connection>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = conn;
    }
}

#[derive(Default)]
struct Dirty {
    units: bool,
    files: bool,
    paths: HashSet<String>,
    lost: bool,
}

fn lock(dirty: &Mutex<Dirty>) -> MutexGuard<'_, Dirty> {
    dirty.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Clone, Debug, PartialEq)]
struct Listed {
    name: String,
    description: String,
    load: String,
    active: String,
    sub: String,
    path: String,
    job: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Service {
    main_pid: u32,
    result: String,
    exec_main_code: u32,
    exec_main_status: i32,
    restarts: u32,
}

/// The unit files by unit name: the file's path and how it is installed.
type Files = HashMap<String, (String, String)>;

struct UnitsCollector {
    feed: Feed,
    waker: Waker,
    board: Board<String, UnitStatus>,
    latest: Latest<Vec<Unit>>,
    bus: Bus,
    dirty: Arc<Mutex<Dirty>>,
    listed: Vec<Listed>,
    files: Files,
    main_pids: HashMap<String, u32>,
    services: HashMap<String, Service>,
    attempts: u32,
    warned: bool,
}

/// Follows systemd on a thread of its own; without a system bus the list stays empty.
pub fn start(feed: Feed) -> anyhow::Result<(Monitor, Units)> {
    let (waker, wakes) = monitor::channel();
    let (following, board) = board({
        let waker = waker.clone();
        move || waker.wake()
    });
    let latest = Latest::new(Vec::new());
    let bus = Bus::default();
    let collector = UnitsCollector {
        feed,
        waker,
        board,
        latest: latest.clone(),
        bus: bus.clone(),
        dirty: Arc::default(),
        listed: Vec::new(),
        files: Files::new(),
        main_pids: HashMap::new(),
        services: HashMap::new(),
        attempts: 0,
        warned: false,
    };
    let monitor = Monitor::start("units", SPACING, wakes, collector)?;
    let units = Units {
        latest,
        following,
        runner: Runner::start("unit-jobs", JOB_WORKERS)?,
        bus,
    };
    Ok((monitor, units))
}

impl Collector for UnitsCollector {
    fn tick(&mut self, _: Why) -> Instant {
        match self.collect() {
            Ok(next) => next,
            Err(e) => {
                if !self.warned {
                    tracing::warn!("systemd: {e:#}");
                    self.warned = true;
                }
                self.disconnect();
                Instant::now() + RECONNECT
            }
        }
    }
}

impl UnitsCollector {
    fn collect(&mut self) -> anyhow::Result<Instant> {
        let conn = match self.bus.get() {
            Some(conn) => conn,
            None => self.connect()?,
        };
        let dirty = std::mem::take(&mut *lock(&self.dirty));
        if dirty.lost {
            anyhow::bail!("the system bus connection closed");
        }
        if dirty.files {
            self.files = list_unit_files(&conn)?;
        }
        if dirty.units {
            self.listed = list_units(&conn)?;
            let names: HashSet<&str> = self.listed.iter().map(|l| l.name.as_str()).collect();
            self.main_pids.retain(|name, _| names.contains(name.as_str()));
        }
        for path in &dirty.paths {
            if let Some(listed) = self.listed.iter().find(|l| l.path == *path) {
                self.main_pids.remove(&listed.name);
                self.services.remove(&listed.name);
            }
        }
        self.read_main_pids(&conn);

        let resolver = self.resolver();
        let mut unresolved = false;
        self.latest.set(compose(&self.listed, &self.files, &self.main_pids, &mut |pid| {
            resolve(&resolver, pid, &mut unresolved)
        }));

        let (listed, files) = (&self.listed, &self.files);
        self.board.take_requests(|name| known(listed, files, name));
        self.follow(&conn, &resolver, &mut unresolved);
        for name in self.board.sweep(Instant::now()) {
            self.services.remove(&name);
        }

        let now = Instant::now();
        if !unresolved {
            self.attempts = 0;
            return Ok(now + IDLE);
        }
        if self.attempts >= RESOLVE_ATTEMPTS {
            return Ok(now + IDLE);
        }
        self.attempts += 1;
        self.feed.wake();
        Ok(now + RESOLVE_RETRY)
    }

    fn connect(&mut self) -> anyhow::Result<Connection> {
        let conn = Connection::system()?;
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(DESTINATION)?
            .build();
        let signals = MessageIterator::for_match_rule(rule, &conn, Some(1024))?;
        conn.call_method(Some(DESTINATION), MANAGER_PATH, Some(MANAGER), "Subscribe", &())?;
        *lock(&self.dirty) = Dirty {
            units: true,
            files: true,
            ..Dirty::default()
        };
        let (dirty, waker) = (self.dirty.clone(), self.waker.clone());
        std::thread::Builder::new()
            .name("units-signals".into())
            .spawn(move || listen(signals, dirty, waker))?;
        self.bus.set(Some(conn.clone()));
        if self.warned {
            tracing::info!("systemd: connected");
            self.warned = false;
        }
        Ok(conn)
    }

    fn disconnect(&mut self) {
        if let Some(conn) = self.bus.get() {
            self.bus.set(None);
            let _ = conn.close();
        }
        self.listed.clear();
        self.files.clear();
        self.main_pids.clear();
        self.services.clear();
        self.latest.set(Vec::new());
        self.board.take_requests(|_| false);
        let followed: Vec<String> = self.board.keys().cloned().collect();
        for name in &followed {
            self.board.end(name);
        }
    }

    fn read_main_pids(&mut self, conn: &Connection) {
        for listed in &self.listed {
            if listed.name.ends_with(".service") && runs(&listed.active) && !self.main_pids.contains_key(&listed.name) {
                let pid = property(conn, &listed.path, SERVICE, "MainPID").unwrap_or(0);
                self.main_pids.insert(listed.name.clone(), pid);
            }
        }
    }

    fn resolver(&self) -> HashMap<u32, Key> {
        let Ok(snapshot) = self.feed.latest.get() else {
            return HashMap::new();
        };
        snapshot
            .value
            .passports
            .value
            .values()
            .filter(|p| p.view_pid != 0)
            .map(|p| (p.view_pid, p.key))
            .collect()
    }

    fn follow(&mut self, conn: &Connection, resolver: &HashMap<u32, Key>, unresolved: &mut bool) {
        let followed: Vec<String> = self.board.keys().cloned().collect();
        for name in followed {
            let listed = self.listed.iter().find(|l| l.name == name);
            if listed.is_none() && !self.files.contains_key(&name) {
                self.board.end(&name);
                self.services.remove(&name);
                continue;
            }
            let service = match listed {
                Some(l) if name.ends_with(".service") => self
                    .services
                    .entry(name.clone())
                    .or_insert_with(|| service(conn, &l.path))
                    .clone(),
                _ => Service::default(),
            };
            let status = status_of(listed, &service, &mut |pid| resolve(resolver, pid, unresolved));
            self.board.publish(&name, status);
        }
    }
}

fn listen(signals: MessageIterator, dirty: Arc<Mutex<Dirty>>, waker: Waker) {
    for message in signals {
        let Ok(message) = message else {
            break;
        };
        let header = message.header();
        let files = header
            .member()
            .is_some_and(|m| matches!(m.as_str(), "UnitFilesChanged" | "Reloading"));
        let path = header
            .path()
            .map(|p| p.as_str())
            .filter(|p| p.starts_with(UNIT_PATHS))
            .map(str::to_owned);
        {
            let mut dirty = lock(&dirty);
            dirty.units = true;
            dirty.files |= files;
            dirty.paths.extend(path);
        }
        waker.wake();
    }
    lock(&dirty).lost = true;
    waker.wake();
}

fn resolve(resolver: &HashMap<u32, Key>, pid: u32, unresolved: &mut bool) -> Option<Key> {
    if pid == 0 {
        return None;
    }
    let key = resolver.get(&pid).copied();
    *unresolved |= key.is_none();
    key
}

fn known(listed: &[Listed], files: &Files, name: &str) -> bool {
    files.contains_key(name) || listed.iter().any(|l| l.name == name)
}

fn runs(active: &str) -> bool {
    matches!(active, "active" | "reloading" | "activating" | "deactivating" | "refreshing")
}

type ListUnitsRow = (String, String, String, String, String, String, OwnedObjectPath, u32, String, OwnedObjectPath);

fn list_units(conn: &Connection) -> zbus::Result<Vec<Listed>> {
    let reply = conn.call_method(Some(DESTINATION), MANAGER_PATH, Some(MANAGER), "ListUnits", &())?;
    let rows: Vec<ListUnitsRow> = reply.body().deserialize()?;
    Ok(rows
        .into_iter()
        .map(|(name, description, load, active, sub, _, path, _, job, _)| Listed {
            name,
            description,
            load,
            active,
            sub,
            path: path.to_string(),
            job,
        })
        .collect())
}

fn list_unit_files(conn: &Connection) -> zbus::Result<Files> {
    let reply = conn.call_method(Some(DESTINATION), MANAGER_PATH, Some(MANAGER), "ListUnitFiles", &())?;
    let rows: Vec<(String, String)> = reply.body().deserialize()?;
    Ok(files_by_name(rows))
}

fn files_by_name(rows: Vec<(String, String)>) -> Files {
    let mut files = Files::new();
    for (path, state) in rows {
        let Some(name) = path.rsplit('/').next().filter(|n| !n.is_empty() && !n.contains("@.")) else {
            continue;
        };
        files.entry(name.to_owned()).or_insert((path, state));
    }
    files
}

fn property<T: TryFrom<OwnedValue>>(conn: &Connection, path: &str, interface: &str, name: &str) -> Option<T> {
    let reply = conn
        .call_method(Some(DESTINATION), path, Some(PROPERTIES), "Get", &(interface, name))
        .ok()?;
    let value: OwnedValue = reply.body().deserialize().ok()?;
    T::try_from(value).ok()
}

fn service(conn: &Connection, path: &str) -> Service {
    let all: HashMap<String, OwnedValue> = conn
        .call_method(Some(DESTINATION), path, Some(PROPERTIES), "GetAll", &(SERVICE,))
        .ok()
        .and_then(|reply| reply.body().deserialize().ok())
        .unwrap_or_default();
    let get = |name: &str| all.get(name).and_then(|v| v.try_clone().ok());
    Service {
        main_pid: get("MainPID").and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
        result: get("Result").and_then(|v| String::try_from(v).ok()).unwrap_or_default(),
        exec_main_code: get("ExecMainCode").and_then(|v| i32::try_from(v).ok()).unwrap_or(0) as u32,
        exec_main_status: get("ExecMainStatus").and_then(|v| i32::try_from(v).ok()).unwrap_or(0),
        restarts: get("NRestarts").and_then(|v| u32::try_from(v).ok()).unwrap_or(0),
    }
}

fn compose(
    listed: &[Listed],
    files: &Files,
    main_pids: &HashMap<String, u32>,
    resolve: &mut impl FnMut(u32) -> Option<Key>,
) -> Vec<Unit> {
    let file = |name: &str| match files.get(name) {
        Some((path, state)) => (path.clone(), file_state(state)),
        None => (String::new(), UnitFileState::Unknown),
    };
    let mut units: Vec<Unit> = listed
        .iter()
        .map(|l| {
            let (file, file_state) = file(&l.name);
            let main = match main_pids.get(&l.name) {
                Some(&pid) if runs(&l.active) => resolve(pid),
                _ => None,
            };
            Unit {
                name: l.name.clone(),
                description: l.description.clone(),
                load: load_state(&l.load),
                active: active_state(&l.active),
                sub: l.sub.clone(),
                file_state,
                file,
                main,
                job: job(&l.job),
            }
        })
        .collect();
    let loaded: HashSet<&str> = listed.iter().map(|l| l.name.as_str()).collect();
    units.extend(
        files
            .iter()
            .filter(|(name, _)| !loaded.contains(name.as_str()))
            .map(|(name, (path, state))| Unit {
                name: name.clone(),
                description: String::new(),
                load: UnitLoadState::Unloaded,
                active: UnitActiveState::Inactive,
                sub: "dead".into(),
                file_state: file_state(state),
                file: path.clone(),
                main: None,
                job: UnitJob::None,
            }),
    );
    units.sort_by(|a, b| a.name.cmp(&b.name));
    units
}

fn status_of(
    listed: Option<&Listed>,
    service: &Service,
    resolve: &mut impl FnMut(u32) -> Option<Key>,
) -> UnitStatus {
    let Some(l) = listed else {
        return UnitStatus {
            load: UnitLoadState::Unloaded,
            active: UnitActiveState::Inactive,
            sub: "dead".into(),
            main: None,
            job: UnitJob::None,
            result: String::new(),
            exec_main_code: 0,
            exec_main_status: 0,
            restarts: 0,
        };
    };
    UnitStatus {
        load: load_state(&l.load),
        active: active_state(&l.active),
        sub: l.sub.clone(),
        main: if runs(&l.active) { resolve(service.main_pid) } else { None },
        job: job(&l.job),
        result: service.result.clone(),
        exec_main_code: service.exec_main_code,
        exec_main_status: service.exec_main_status,
        restarts: service.restarts,
    }
}

fn load_state(s: &str) -> UnitLoadState {
    match s {
        "loaded" => UnitLoadState::Loaded,
        "not-found" => UnitLoadState::NotFound,
        "bad-setting" => UnitLoadState::BadSetting,
        "error" => UnitLoadState::Error,
        "merged" => UnitLoadState::Merged,
        "masked" => UnitLoadState::Masked,
        "stub" => UnitLoadState::Stub,
        _ => UnitLoadState::Unknown,
    }
}

fn active_state(s: &str) -> UnitActiveState {
    match s {
        "active" => UnitActiveState::Active,
        "reloading" => UnitActiveState::Reloading,
        "inactive" => UnitActiveState::Inactive,
        "failed" => UnitActiveState::Failed,
        "activating" => UnitActiveState::Activating,
        "deactivating" => UnitActiveState::Deactivating,
        "maintenance" => UnitActiveState::Maintenance,
        "refreshing" => UnitActiveState::Refreshing,
        _ => UnitActiveState::Unknown,
    }
}

fn file_state(s: &str) -> UnitFileState {
    match s {
        "enabled" => UnitFileState::Enabled,
        "enabled-runtime" => UnitFileState::EnabledRuntime,
        "linked" => UnitFileState::Linked,
        "linked-runtime" => UnitFileState::LinkedRuntime,
        "alias" => UnitFileState::Alias,
        "masked" => UnitFileState::Masked,
        "masked-runtime" => UnitFileState::MaskedRuntime,
        "static" => UnitFileState::Static,
        "disabled" => UnitFileState::Disabled,
        "indirect" => UnitFileState::Indirect,
        "generated" => UnitFileState::Generated,
        "transient" => UnitFileState::Transient,
        "bad" => UnitFileState::Bad,
        _ => UnitFileState::Unknown,
    }
}

fn job(s: &str) -> UnitJob {
    match s {
        "" => UnitJob::None,
        "start" => UnitJob::Start,
        "verify-active" => UnitJob::VerifyActive,
        "stop" => UnitJob::Stop,
        "reload" => UnitJob::Reload,
        "restart" => UnitJob::Restart,
        "try-restart" => UnitJob::TryRestart,
        "try-reload" => UnitJob::TryReload,
        "reload-or-start" => UnitJob::ReloadOrStart,
        _ => UnitJob::Unknown,
    }
}

fn errno(e: &zbus::Error) -> u32 {
    (match e {
        zbus::Error::MethodError(name, _, _) => errno_of(name.as_str()),
        zbus::Error::FDO(e) => errno_of(e.name().as_str()),
        _ => libc::EIO,
    }) as u32
}

fn errno_of(error_name: &str) -> i32 {
    match error_name {
        "org.freedesktop.systemd1.NoSuchUnit" => libc::ENOENT,
        "org.freedesktop.DBus.Error.AccessDenied"
        | "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired" => libc::EACCES,
        "org.freedesktop.systemd1.JobTypeNotApplicable" => libc::EBADR,
        "org.freedesktop.systemd1.UnitMasked" => libc::ERFKILL,
        "org.freedesktop.systemd1.TransactionJobsConflicting"
        | "org.freedesktop.systemd1.TransactionOrderIsCyclic"
        | "org.freedesktop.systemd1.TransactionIsDestructive" => libc::EDEADLK,
        _ => libc::EIO,
    }
}

#[cfg(test)]
impl Units {
    /// Units with no systemd behind them, and the board a test publishes statuses on.
    pub fn detached() -> (Self, Board<String, UnitStatus>) {
        let (following, board) = board(|| {});
        let units = Self {
            latest: Latest::new(Vec::new()),
            following,
            runner: Runner::start("unit-jobs", 1).unwrap(),
            bus: Bus::default(),
        };
        (units, board)
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use super::*;

    fn listed(name: &str, active: &str, job: &str) -> Listed {
        Listed {
            name: name.into(),
            description: format!("{name} unit"),
            load: "loaded".into(),
            active: active.into(),
            sub: if active == "active" { "running".into() } else { "dead".into() },
            path: format!("{UNIT_PATHS}{}", name.replace('.', "_2e")),
            job: job.into(),
        }
    }

    fn key(pid: u32) -> Key {
        Key {
            pid: pid + 1000,
            sequence_number: pid as u64,
        }
    }

    #[test]
    fn unit_files_are_keyed_by_name_without_templates() {
        let files = files_by_name(vec![
            ("/usr/lib/systemd/system/ssh.service".into(), "enabled".into()),
            ("/usr/lib/systemd/system/getty@.service".into(), "enabled".into()),
            ("/etc/systemd/system/ssh.service".into(), "masked".into()),
        ]);
        assert_eq!(files.len(), 1);
        assert_eq!(files["ssh.service"], ("/usr/lib/systemd/system/ssh.service".into(), "enabled".into()));
    }

    #[test]
    fn loaded_units_come_with_their_files_and_unloaded_files_follow() {
        let files = files_by_name(vec![
            ("/usr/lib/systemd/system/ssh.service".into(), "enabled".into()),
            ("/usr/lib/systemd/system/rsync.service".into(), "disabled".into()),
        ]);
        let listed = vec![listed("ssh.service", "active", ""), listed("dev-sda.device", "active", "")];
        let main_pids = HashMap::from([("ssh.service".to_string(), 42)]);
        let units = compose(&listed, &files, &main_pids, &mut |pid| Some(key(pid)));

        let names: Vec<&str> = units.iter().map(|u| u.name.as_str()).collect();
        assert_eq!(names, ["dev-sda.device", "rsync.service", "ssh.service"]);
        let ssh = &units[2];
        assert_eq!(ssh.load, UnitLoadState::Loaded);
        assert_eq!(ssh.active, UnitActiveState::Active);
        assert_eq!(ssh.file_state, UnitFileState::Enabled);
        assert_eq!(ssh.main, Some(key(42)));
        assert_eq!(ssh.job, UnitJob::None);
        let rsync = &units[1];
        assert_eq!(rsync.load, UnitLoadState::Unloaded);
        assert_eq!(rsync.file_state, UnitFileState::Disabled);
        assert_eq!(rsync.file, "/usr/lib/systemd/system/rsync.service");
        assert_eq!(units[0].file_state, UnitFileState::Unknown);
        assert!(units[0].file.is_empty());
    }

    #[test]
    fn a_stopped_service_has_no_main_process_whatever_was_cached() {
        let listed = vec![listed("ssh.service", "inactive", "start")];
        let main_pids = HashMap::from([("ssh.service".to_string(), 42)]);
        let units = compose(&listed, &Files::new(), &main_pids, &mut |_| panic!("not asked"));
        assert_eq!(units[0].main, None);
        assert_eq!(units[0].job, UnitJob::Start);
    }

    #[test]
    fn a_main_pid_the_snapshot_lacks_is_unresolved() {
        let resolver = HashMap::from([(7, key(7))]);
        let mut unresolved = false;
        assert_eq!(resolve(&resolver, 0, &mut unresolved), None);
        assert!(!unresolved);
        assert_eq!(resolve(&resolver, 7, &mut unresolved), Some(key(7)));
        assert!(!unresolved);
        assert_eq!(resolve(&resolver, 8, &mut unresolved), None);
        assert!(unresolved);
    }

    #[test]
    fn a_status_carries_the_service_result() {
        let service = Service {
            main_pid: 9,
            result: "exit-code".into(),
            exec_main_code: 1,
            exec_main_status: 3,
            restarts: 2,
        };
        let status = status_of(Some(&listed("x.service", "activating", "start")), &service, &mut |pid| Some(key(pid)));
        assert_eq!(status.active, UnitActiveState::Activating);
        assert_eq!(status.main, Some(key(9)));
        assert_eq!(status.job, UnitJob::Start);
        assert_eq!((status.result.as_str(), status.exec_main_code, status.exec_main_status, status.restarts), ("exit-code", 1, 3, 2));

        let unloaded = status_of(None, &Service::default(), &mut |_| panic!("not asked"));
        assert_eq!(unloaded.load, UnitLoadState::Unloaded);
        assert_eq!(unloaded.active, UnitActiveState::Inactive);
    }

    #[test]
    fn systemd_strings_map_to_the_wire_enums() {
        assert_eq!(load_state("not-found"), UnitLoadState::NotFound);
        assert_eq!(load_state("?"), UnitLoadState::Unknown);
        assert_eq!(active_state("deactivating"), UnitActiveState::Deactivating);
        assert_eq!(file_state("enabled-runtime"), UnitFileState::EnabledRuntime);
        assert_eq!(job("reload-or-start"), UnitJob::ReloadOrStart);
        assert_eq!(job("nop"), UnitJob::Unknown);
    }

    struct TestUnit(&'static str);

    impl TestUnit {
        fn install(name: &'static str, body: &str) -> Self {
            std::fs::write(format!("/run/systemd/system/{name}"), body).unwrap();
            daemon_reload();
            Self(name)
        }
    }

    impl Drop for TestUnit {
        fn drop(&mut self) {
            let _ = std::process::Command::new("systemctl").args(["stop", self.0]).status();
            let _ = std::fs::remove_file(format!("/run/systemd/system/{}", self.0));
            daemon_reload();
        }
    }

    fn daemon_reload() {
        assert!(std::process::Command::new("systemctl").arg("daemon-reload").status().unwrap().success());
    }

    fn run(units: &Units, name: &str, method: &'static str) -> u32 {
        futures::executor::block_on(units.command(name.into(), method).unwrap()).unwrap()
    }

    fn until_listed(units: &Units, what: impl Fn(&Unit) -> bool) -> Unit {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(unit) = units.list().value.iter().find(|u| what(u)) {
                return unit.clone();
            }
            assert!(Instant::now() < deadline, "timed out");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    #[ignore = "drives the distro's systemd and puts a unit in /run: needs root, BTF and systemd"]
    fn the_live_systemd_lists_starts_watches_and_stops_a_unit() {
        let (_feed_monitor, feed) = crate::feed::start().unwrap();
        let (_monitor, units) = start(feed).unwrap();
        let journald = until_listed(&units, |u| u.name == "systemd-journald.service" && u.main.is_some());
        eprintln!("{} units; {journald:?}", units.list().value.len());
        assert_eq!(journald.active, UnitActiveState::Active);
        assert_eq!(journald.file_state, UnitFileState::Static);

        let name = "uniproc-agent-test.service";
        let _unit = TestUnit::install(name, "[Service]\nExecStart=/bin/sleep 300\n");
        until_listed(&units, |u| u.name == name);
        let statuses = units.watch(name.into());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            futures::executor::block_on(statuses.for_each(|s| {
                let _ = tx.send(s);
                futures::future::ready(())
            }))
        });
        let next = |what: &dyn Fn(&UnitStatus) -> bool| loop {
            let status = rx.recv_timeout(Duration::from_secs(5)).expect("a status");
            eprintln!("{status:?}");
            if what(&status) {
                return status;
            }
        };
        next(&|s| s.active == UnitActiveState::Inactive);

        assert_eq!(run(&units, name, "StartUnit"), 0);
        let running = next(&|s| s.active == UnitActiveState::Active && s.main.is_some());
        assert_eq!(running.sub, "running");
        let listed = until_listed(&units, |u| u.name == name && u.main.is_some());
        assert_eq!(listed.main, running.main);

        assert_eq!(run(&units, name, "ReloadUnit"), libc::EBADR as u32);
        assert_eq!(run(&units, "no-such-unit-uniproc.service", "StartUnit"), libc::ENOENT as u32);

        assert_eq!(run(&units, name, "StopUnit"), 0);
        let stopped = next(&|s| s.active == UnitActiveState::Inactive);
        assert_eq!(stopped.main, None);
        assert!(matches!(stopped.load, UnitLoadState::Loaded | UnitLoadState::Unloaded));
    }

    #[test]
    fn bus_errors_map_to_the_documented_errnos() {
        assert_eq!(errno_of("org.freedesktop.systemd1.NoSuchUnit"), libc::ENOENT);
        assert_eq!(errno_of("org.freedesktop.systemd1.UnitMasked"), libc::ERFKILL);
        assert_eq!(errno_of("org.freedesktop.systemd1.JobTypeNotApplicable"), libc::EBADR);
        assert_eq!(errno_of("org.freedesktop.DBus.Error.AccessDenied"), libc::EACCES);
        assert_eq!(errno_of("org.freedesktop.systemd1.TransactionIsDestructive"), libc::EDEADLK);
        assert_eq!(errno_of("org.freedesktop.DBus.Error.InvalidArgs"), libc::EIO);
    }
}
