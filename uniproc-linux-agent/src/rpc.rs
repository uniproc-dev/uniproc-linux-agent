//! capnp RPC front-end, mirroring uniproc-windows-agent's src/rpc:
//! `Endpoint` + `accept_session` + a `linux_agent::Server` impl.
//!
//! One listener: vsock port 5000, which the host (Windows) dials in from
//! outside the VM. There used to be a second one on a uds socket for in-guest
//! clients, but nothing consumes it - anything running inside the VM can read
//! the same data straight from /proc.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use futures::future::{AbortHandle, Abortable};
use ogurpchik::auth::handshake::{HandshakeMode, Protocol};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::net::Listener;
use ogurpchik::net::vsock::VsockTarget;
use ogurpchik::rpc::accept_session;
use uniproc_agent_kit::Tagged;
use uniproc_protocol::linux_capnp::{agent_listener, linux_agent, lists_update, watch_handle};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::{LINUX_PROTOCOL, WSL_AGENT_VSOCK_PORT};

use crate::commands;
use crate::feed::Feed;
use crate::model::{Key, Passports, Snapshot, States};
use crate::wire::{self, Wanted};

const MIN_INTERVAL: Duration = Duration::from_millis(100);
const MAX_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct AgentImpl {
    feed: Feed,
}

impl AgentImpl {
    fn snapshot(&self) -> std::result::Result<Arc<Snapshot>, capnp::Error> {
        self.feed
            .latest
            .get()
            .map(|tagged| tagged.value)
            .map_err(|e| capnp::Error::failed(format!("collect failed: {e}")))
    }

    fn command(&self, pid: u32, sequence_number: u64, run: impl FnOnce(u32) -> u32) -> u32 {
        let Ok(snapshot) = self.snapshot() else {
            return libc::EAGAIN as u32;
        };
        let range = Key { pid, sequence_number: 0 }..=Key { pid, sequence_number: u64::MAX };
        let found = snapshot
            .passports
            .value
            .range(range)
            .map(|(_, p)| p)
            .find(|p| sequence_number == 0 || p.key.sequence_number == sequence_number);
        match found {
            None => libc::ESRCH as u32,
            Some(p) if p.view_pid == 0 => libc::EPERM as u32,
            Some(p) => run(p.view_pid),
        }
    }
}

fn answer<T>(
    tagged: &Tagged<T>,
    if_none_match: u64,
    mut meta: response_meta::Builder,
) -> bool {
    meta.set_etag(tagged.etag);
    if tagged.unchanged_since(if_none_match) {
        meta.set_status(ResponseStatus::NotModified);
        return false;
    }
    meta.set_status(ResponseStatus::Ok);
    true
}

impl linux_agent::Server for AgentImpl {
    async fn ping(
        self: Rc<Self>,
        params: linux_agent::PingParams,
        mut results: linux_agent::PingResults,
    ) -> std::result::Result<(), capnp::Error> {
        let nonce = params.get()?.get_nonce();
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_nonce(nonce);
        Ok(())
    }

    async fn get_processes(
        self: Rc<Self>,
        params: linux_agent::GetProcessesParams,
        mut results: linux_agent::GetProcessesResults,
    ) -> std::result::Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let snapshot = self.snapshot()?;
        let mut out = results.get();
        if !answer(&snapshot.passports, if_none_match, out.reborrow().init_meta()) {
            return Ok(());
        }
        let passports = &snapshot.passports.value;
        let mut list = out.init_processes(passports.len() as u32);
        for (i, passport) in passports.values().enumerate() {
            wire::process_info(passport, list.reborrow().get(i as u32));
        }
        Ok(())
    }

    async fn get_process_states(
        self: Rc<Self>,
        params: linux_agent::GetProcessStatesParams,
        mut results: linux_agent::GetProcessStatesResults,
    ) -> std::result::Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let snapshot = self.snapshot()?;
        let mut out = results.get();
        if !answer(&snapshot.states, if_none_match, out.reborrow().init_meta()) {
            return Ok(());
        }
        out.set_passport_etag(snapshot.passports.etag);
        let states = &snapshot.states.value;
        let mut list = out.init_states(states.len() as u32);
        for (i, state) in states.values().enumerate() {
            wire::process_state(state, list.reborrow().get(i as u32));
        }
        Ok(())
    }

    async fn get_environments(
        self: Rc<Self>,
        params: linux_agent::GetEnvironmentsParams,
        mut results: linux_agent::GetEnvironmentsResults,
    ) -> std::result::Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let snapshot = self.snapshot()?;
        let mut out = results.get();
        if !answer(&snapshot.environments, if_none_match, out.reborrow().init_meta()) {
            return Ok(());
        }
        let e = &snapshot.environments.value;
        wire::environments(e, out.reborrow().init_environments(e.environments.len() as u32));
        wire::docker_containers(e, out.init_docker_containers(e.docker_containers.len() as u32));
        Ok(())
    }

    async fn watch(
        self: Rc<Self>,
        params: linux_agent::WatchParams,
        mut results: linux_agent::WatchResults,
    ) -> std::result::Result<(), capnp::Error> {
        let params = params.get()?;
        let spec = params.get_spec()?;
        let interval = watch_interval(spec.get_interval_ms());
        let wanted = Wanted::read(spec)?;
        let listener = params.get_listener()?;
        let (abort, registration) = AbortHandle::new_pair();
        compio::runtime::spawn(Abortable::new(
            push(self.feed.clone(), interval, wanted, listener),
            registration,
        ))
        .detach();
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_handle(capnp_rpc::new_client(WatchHandleImpl(abort)));
        Ok(())
    }

    async fn kill(
        self: Rc<Self>,
        params: linux_agent::KillParams,
        mut results: linux_agent::KillResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let seq = p.get_sequence_number();
        let code = self.command(p.get_pid(), seq, |pid| commands::signal(pid, seq, libc::SIGKILL as u32));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn terminate(
        self: Rc<Self>,
        params: linux_agent::TerminateParams,
        mut results: linux_agent::TerminateResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let seq = p.get_sequence_number();
        let code = self.command(p.get_pid(), seq, |pid| commands::signal(pid, seq, libc::SIGTERM as u32));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn suspend(
        self: Rc<Self>,
        params: linux_agent::SuspendParams,
        mut results: linux_agent::SuspendResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let seq = p.get_sequence_number();
        let code = self.command(p.get_pid(), seq, |pid| commands::signal(pid, seq, libc::SIGSTOP as u32));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn resume(
        self: Rc<Self>,
        params: linux_agent::ResumeParams,
        mut results: linux_agent::ResumeResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let seq = p.get_sequence_number();
        let code = self.command(p.get_pid(), seq, |pid| commands::signal(pid, seq, libc::SIGCONT as u32));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn signal(
        self: Rc<Self>,
        params: linux_agent::SignalParams,
        mut results: linux_agent::SignalResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let seq = p.get_sequence_number();
        let signal = p.get_signal();
        let code = self.command(p.get_pid(), seq, |pid| commands::signal(pid, seq, signal));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn set_nice(
        self: Rc<Self>,
        params: linux_agent::SetNiceParams,
        mut results: linux_agent::SetNiceResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let seq = p.get_sequence_number();
        let nice = p.get_nice();
        let code = self.command(p.get_pid(), seq, |pid| commands::set_nice(pid, seq, nice));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn set_affinity(
        self: Rc<Self>,
        params: linux_agent::SetAffinityParams,
        mut results: linux_agent::SetAffinityResults,
    ) -> std::result::Result<(), capnp::Error> {
        let p = params.get()?;
        let mask: Vec<u64> = p.get_mask()?.iter().collect();
        let seq = p.get_sequence_number();
        let code = self.command(p.get_pid(), seq, |pid| commands::set_affinity(pid, seq, &mask));
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }
}

struct WatchHandleImpl(AbortHandle);

impl watch_handle::Server for WatchHandleImpl {}

impl Drop for WatchHandleImpl {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn watch_interval(interval_ms: u32) -> Duration {
    if interval_ms == 0 {
        return DEFAULT_INTERVAL;
    }
    Duration::from_millis(interval_ms.into()).clamp(MIN_INTERVAL, MAX_INTERVAL)
}

/// What a listener last received: the lists its next deltas apply to.
struct Sent {
    number: u64,
    passports: Tagged<Arc<Passports>>,
    states: Tagged<Arc<States>>,
    environments_etag: u64,
}

impl Sent {
    fn of(snapshot: &Snapshot) -> Self {
        Self {
            number: snapshot.number,
            passports: snapshot.passports.clone(),
            states: snapshot.states.clone(),
            environments_etag: snapshot.environments.etag,
        }
    }
}

async fn push(feed: Feed, interval: Duration, wanted: Wanted, listener: agent_listener::Client) {
    let _lease = feed.lease(interval);
    let mut generation = feed.fresh.generation();
    let mut sent: Option<Sent> = None;
    loop {
        if let Ok(current) = feed.latest.get()
            && sent.as_ref().is_none_or(|s| s.number != current.value.number)
        {
            let snapshot = &current.value;
            let started = Instant::now();
            let mut request = listener.update_request();
            let mut out = request.get();
            out.reborrow().init_meta();
            lists(sent.as_ref(), snapshot, out.reborrow().init_lists());
            wire::columns(snapshot, wanted, out.reborrow().init_processes());
            wire::machine(snapshot, wanted, out.init_machine());
            if let Err(e) = request.send().promise.await {
                tracing::info!("watch ended by its listener: {e}");
                return;
            }
            sent = Some(Sent::of(snapshot));
            compio::time::sleep(interval.saturating_sub(started.elapsed())).await;
        }
        generation = feed.fresh.changed(generation).await;
    }
}

/// Keys that left `base`, and rows of `now` that are new or differ from `base`.
fn changes<'a, V: PartialEq>(
    base: &BTreeMap<Key, V>,
    now: &'a BTreeMap<Key, V>,
) -> (Vec<Key>, Vec<&'a V>) {
    let left = base.keys().filter(|k| !now.contains_key(k)).copied().collect();
    let upserted = now
        .iter()
        .filter(|(k, v)| base.get(k) != Some(v))
        .map(|(_, v)| v)
        .collect();
    (left, upserted)
}

fn lists(sent: Option<&Sent>, snapshot: &Snapshot, mut out: lists_update::Builder) {
    out.set_passport_etag(snapshot.passports.etag);
    out.set_states_etag(snapshot.states.etag);
    out.set_environments_etag(snapshot.environments.etag);

    let passports = &snapshot.passports.value;
    match sent.map(|s| &s.passports) {
        Some(base) if base.etag == snapshot.passports.etag => {
            out.reborrow().init_passports().set_unchanged(())
        }
        Some(base) => {
            let (left, upserted) = changes(&base.value, passports);
            let mut delta = out.reborrow().init_passports().init_delta();
            delta.set_base_etag(base.etag);
            let mut list = delta.reborrow().init_left(left.len() as u32);
            for (i, key) in left.iter().enumerate() {
                wire::process_key(*key, list.reborrow().get(i as u32));
            }
            let mut list = delta.init_upserted(upserted.len() as u32);
            for (i, passport) in upserted.iter().enumerate() {
                wire::process_info(passport, list.reborrow().get(i as u32));
            }
        }
        None => {
            let mut list = out.reborrow().init_passports().init_full(passports.len() as u32);
            for (i, passport) in passports.values().enumerate() {
                wire::process_info(passport, list.reborrow().get(i as u32));
            }
        }
    }

    let states = &snapshot.states.value;
    match sent.map(|s| &s.states) {
        Some(base) if base.etag == snapshot.states.etag => {
            out.reborrow().init_states().set_unchanged(())
        }
        Some(base) => {
            let (left, upserted) = changes(&base.value, states);
            let mut delta = out.reborrow().init_states().init_delta();
            delta.set_base_etag(base.etag);
            let mut list = delta.reborrow().init_left(left.len() as u32);
            for (i, key) in left.iter().enumerate() {
                wire::process_key(*key, list.reborrow().get(i as u32));
            }
            let mut list = delta.init_upserted(upserted.len() as u32);
            for (i, state) in upserted.iter().enumerate() {
                wire::process_state(state, list.reborrow().get(i as u32));
            }
        }
        None => {
            let mut list = out.reborrow().init_states().init_full(states.len() as u32);
            for (i, state) in states.values().enumerate() {
                wire::process_state(state, list.reborrow().get(i as u32));
            }
        }
    }

    match sent {
        Some(s) if s.environments_etag == snapshot.environments.etag => {
            out.init_environments().set_unchanged(())
        }
        _ => {
            let e = &snapshot.environments.value;
            let mut full = out.init_environments().init_full();
            wire::environments(e, full.reborrow().init_environments(e.environments.len() as u32));
            wire::docker_containers(e, full.init_docker_containers(e.docker_containers.len() as u32));
        }
    }
}

fn uncacheable(mut meta: response_meta::Builder) {
    meta.set_etag(0);
    meta.set_status(ResponseStatus::Ok);
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use uniproc_agent_kit::{Epoch, Versioned};
    use uniproc_protocol::linux_capnp::{MachineMetric, ProcessMetric, lists_update};

    use super::*;
    use crate::model::{Environments, Machine, MachineMemory, Passport, Row, SchedPolicy, State, TaskState};

    fn key(pid: u32) -> Key {
        Key {
            pid,
            sequence_number: 1_000 + pid as u64,
        }
    }

    fn passport(pid: u32) -> Arc<Passport> {
        passport_at(key(pid))
    }

    fn passport_at(key: Key) -> Arc<Passport> {
        let pid = key.pid;
        Arc::new(Passport {
            key,
            view_pid: pid,
            parent_pid: 1,
            start_time: 0,
            name: format!("p{pid}"),
            exe_path: String::new(),
            cmdline: vec![format!("p{pid}"), "-x".into()],
            uid: 0,
            user: "root".into(),
            local_pid: pid,
            mnt_ns: 1,
            pid_ns: 2,
            cgroup: "/".into(),
        })
    }

    fn state(pid: u32, nice: i32) -> State {
        State {
            key: key(pid),
            state: TaskState::Sleeping,
            nice,
            policy: SchedPolicy::Other,
            rt_priority: 0,
        }
    }

    struct Lists {
        passports: Versioned<Arc<Passports>>,
        states: Versioned<Arc<States>>,
        environments: Versioned<Arc<Environments>>,
        number: u64,
    }

    impl Lists {
        fn new() -> Self {
            let epoch = Epoch::new();
            Self {
                passports: Versioned::new(epoch, Arc::default()),
                states: Versioned::new(epoch, Arc::default()),
                environments: Versioned::new(epoch, Arc::default()),
                number: 0,
            }
        }

        fn publish(&mut self, feed: &Feed, processes: &[(u32, i32)]) {
            self.passports
                .set(Arc::new(processes.iter().map(|&(pid, _)| (key(pid), passport(pid))).collect()));
            self.states
                .set(Arc::new(processes.iter().map(|&(pid, nice)| (key(pid), state(pid, nice))).collect()));
            self.number += 1;
            let rows = processes
                .iter()
                .map(|&(pid, _)| Row {
                    key: key(pid),
                    cpu_user_time: pid as u64 * 10,
                    ..Default::default()
                })
                .collect();
            feed.latest.replace(Snapshot {
                number: self.number,
                sampled_at: self.number * 100,
                passports: self.passports.get().clone(),
                states: self.states.get().clone(),
                environments: self.environments.get().clone(),
                rows: Arc::new(rows),
                machine: Arc::new(Machine {
                    memory: Some(MachineMemory {
                        total: 4096,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            });
            feed.fresh.notify();
        }
    }

    #[derive(Debug, Default)]
    struct Update {
        passports: String,
        passport_etag: u64,
        states: String,
        pids: Vec<u32>,
        cpu_user_time: Option<Vec<u64>>,
        resident_set_present: bool,
        memory_total: Option<u64>,
        cpu_present: bool,
    }

    fn keys(list: capnp::struct_list::Reader<uniproc_protocol::linux_capnp::process_key::Owned>) -> String {
        list.iter().map(|k| k.get_pid().to_string()).collect::<Vec<_>>().join(",")
    }

    struct Recorder(Rc<RefCell<Vec<Update>>>);

    impl agent_listener::Server for Recorder {
        async fn update(
            self: Rc<Self>,
            params: agent_listener::UpdateParams,
            _: agent_listener::UpdateResults,
        ) -> std::result::Result<(), capnp::Error> {
            let p = params.get()?;
            let lists = p.get_lists()?;
            let passports = match lists.get_passports().which()? {
                lists_update::passports::Unchanged(()) => "unchanged".to_string(),
                lists_update::passports::Full(full) => {
                    let full = full?;
                    format!("full:{}", full.iter().map(|p| p.get_pid().to_string()).collect::<Vec<_>>().join(","))
                }
                lists_update::passports::Delta(delta) => {
                    let delta = delta?;
                    format!(
                        "delta:-{}+{}",
                        keys(delta.get_left()?),
                        delta.get_upserted()?.iter().map(|p| p.get_pid().to_string()).collect::<Vec<_>>().join(",")
                    )
                }
            };
            let states = match lists.get_states().which()? {
                lists_update::states::Unchanged(()) => "unchanged".to_string(),
                lists_update::states::Full(full) => format!("full:{}", full?.len()),
                lists_update::states::Delta(delta) => {
                    let delta = delta?;
                    format!("delta:-{}+{}", keys(delta.get_left()?), delta.get_upserted()?.len())
                }
            };
            let columns = p.get_processes()?;
            let machine = p.get_machine()?;
            self.0.borrow_mut().push(Update {
                passports,
                passport_etag: lists.get_passport_etag(),
                states,
                pids: columns.get_pids()?.iter().collect(),
                cpu_user_time: columns.has_cpu_user_time().then(|| columns.get_cpu_user_time().unwrap().iter().collect()),
                resident_set_present: columns.has_resident_set(),
                memory_total: machine.has_memory().then(|| machine.get_memory().unwrap().get_total()),
                cpu_present: machine.has_cpu(),
            });
            Ok(())
        }

        async fn ended(
            self: Rc<Self>,
            _: agent_listener::EndedParams,
            _: agent_listener::EndedResults,
        ) -> std::result::Result<(), capnp::Error> {
            Ok(())
        }
    }

    async fn until(what: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !what() {
            assert!(Instant::now() < deadline, "timed out");
            compio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn agent(feed: &Feed) -> linux_agent::Client {
        capnp_rpc::new_client(AgentImpl { feed: feed.clone() })
    }

    #[compio::test]
    async fn get_processes_answers_not_modified_while_the_passports_hold() {
        let feed = Feed::without_collector();
        let mut lists = Lists::new();
        lists.publish(&feed, &[(10, 0), (11, 0)]);
        let agent = agent(&feed);

        let response = agent.get_processes_request().send().promise.await.unwrap();
        let answer = response.get().unwrap();
        let etag = answer.get_meta().unwrap().get_etag();
        assert_eq!(answer.get_processes().unwrap().len(), 2);
        assert_eq!(answer.get_processes().unwrap().get(0).get_cmdline().unwrap().len(), 2);

        lists.publish(&feed, &[(10, 5), (11, 0)]);
        let mut request = agent.get_processes_request();
        request.get().init_meta().set_if_none_match(etag);
        let response = request.send().promise.await.unwrap();
        let meta = response.get().unwrap().get_meta().unwrap();
        assert_eq!(meta.get_status().unwrap(), ResponseStatus::NotModified);
        assert!(!response.get().unwrap().has_processes());

        let mut request = agent.get_process_states_request();
        request.get().init_meta().set_if_none_match(etag);
        let response = request.send().promise.await.unwrap();
        let answer = response.get().unwrap();
        assert_eq!(answer.get_meta().unwrap().get_status().unwrap(), ResponseStatus::Ok);
        assert_eq!(answer.get_passport_etag(), etag);
        assert_eq!(answer.get_states().unwrap().get(0).get_nice(), 5);
    }

    #[compio::test]
    async fn a_watch_sends_full_lists_then_deltas_and_only_the_columns_asked_for() {
        let feed = Feed::without_collector();
        let mut lists = Lists::new();
        lists.publish(&feed, &[(10, 0), (11, 0)]);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let mut request = agent(&feed).watch_request();
        {
            let mut spec = request.get().init_spec();
            spec.set_interval_ms(100);
            spec.reborrow().init_processes(1).set(0, ProcessMetric::CpuUserTime);
            spec.init_machine(1).set(0, MachineMetric::Memory);
        }
        request.get().set_listener(capnp_rpc::new_client(Recorder(seen.clone())));
        let response = request.send().promise.await.unwrap();
        let handle = response.get().unwrap().get_handle().unwrap();

        until(|| seen.borrow().len() == 1).await;
        {
            let seen = seen.borrow();
            let first = &seen[0];
            assert_eq!(first.passports, "full:10,11");
            assert_eq!(first.states, "full:2");
            assert_eq!(first.pids, vec![10, 11]);
            assert_eq!(first.cpu_user_time, Some(vec![100, 110]));
            assert!(!first.resident_set_present);
            assert_eq!(first.memory_total, Some(4096));
            assert!(!first.cpu_present);
        }

        lists.publish(&feed, &[(11, 3), (12, 0)]);
        until(|| seen.borrow().len() == 2).await;
        {
            let seen = seen.borrow();
            assert_eq!(seen[1].passports, "delta:-10+12");
            assert_eq!(seen[1].states, "delta:-10+2");
            assert_eq!(seen[1].pids, vec![11, 12]);
            assert_ne!(seen[1].passport_etag, seen[0].passport_etag);
        }

        lists.publish(&feed, &[(11, 3), (12, 0)]);
        until(|| seen.borrow().len() == 3).await;
        assert_eq!(seen.borrow()[2].passports, "unchanged");
        assert_eq!(seen.borrow()[2].states, "unchanged");

        drop(handle);
        drop(response);
        until(|| feed.period() == Duration::from_secs(1)).await;
    }

    #[compio::test]
    async fn commands_reach_the_process_they_name_and_nothing_else() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let ticks = crate::procfs::start_ticks(pid).unwrap();
        let sequence_number = ticks * (1_000_000_000 / crate::procfs::user_hz());
        let feed = Feed::without_collector();
        let child_key = Key { pid, sequence_number };
        let mut snapshot = Snapshot::empty();
        snapshot.passports.value = Arc::new([(child_key, passport_at(child_key))].into_iter().collect());
        feed.latest.replace(snapshot);
        let agent = agent(&feed);

        let mut request = agent.signal_request();
        request.get().set_pid(pid + 1_000_000);
        request.get().set_signal(0);
        let code = request.send().promise.await.unwrap().get().unwrap().get_code();
        assert_eq!(code, libc::ESRCH as u32);

        let mut request = agent.kill_request();
        request.get().set_pid(pid);
        request.get().set_sequence_number(sequence_number + 60_000_000_000);
        let code = request.send().promise.await.unwrap().get().unwrap().get_code();
        assert_eq!(code, libc::ESRCH as u32);

        let mut request = agent.set_nice_request();
        request.get().set_pid(pid);
        request.get().set_sequence_number(sequence_number);
        request.get().set_nice(10);
        assert_eq!(request.send().promise.await.unwrap().get().unwrap().get_code(), 0);
        let nice = unsafe { libc::getpriority(libc::PRIO_PROCESS, pid) };
        assert_eq!(nice, 10);

        let mut request = agent.kill_request();
        request.get().set_pid(pid);
        request.get().set_sequence_number(sequence_number);
        assert_eq!(request.send().promise.await.unwrap().get().unwrap().get_code(), 0);
        let status = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    }

    #[compio::test]
    async fn ping_echoes_its_nonce() {
        let mut request = agent(&Feed::without_collector()).ping_request();
        request.get().set_nonce(0xdead_beef);
        let response = request.send().promise.await.unwrap();
        assert_eq!(response.get().unwrap().get_nonce(), 0xdead_beef);
    }

    #[test]
    fn an_interval_is_clamped_and_zero_means_a_second() {
        assert_eq!(watch_interval(0), Duration::from_secs(1));
        assert_eq!(watch_interval(1), Duration::from_millis(100));
        assert_eq!(watch_interval(500), Duration::from_millis(500));
        assert_eq!(watch_interval(u32::MAX), Duration::from_secs(60));
    }
}

pub async fn run(feed: Feed, secret: Vec<u8>) -> Result<()> {
    // vsock carries no peer identity across the VM boundary - `getpeername`
    // yields a CID, and a PID from another kernel would be meaningless - so
    // `HandshakeMode::signed_process` cannot work here at all; it refuses this
    // transport outright. A shared secret handed over at launch is what proves
    // the host is the process that started us.
    let handshake = HandshakeMode::hmac(secret);

    // On Linux the listen-side target is ignored (binds VMADDR_CID_ANY).
    let vsock = Endpoint::Vsock {
        target: VsockTarget::Cid(0),
        port: WSL_AGENT_VSOCK_PORT,
    };

    // Failing to bind most likely means something else already holds the port -
    // worth being loud about, since that is exactly what an impostor would do.
    let vsock_listener = vsock.listen().await.map_err(|e| {
        anyhow::anyhow!("failed to bind vsock port {WSL_AGENT_VSOCK_PORT}: {e:?}")
    })?;

    tracing::info!(%vsock, "listening");

    serve_loop(vsock_listener, feed, handshake).await
}

async fn serve_loop(listener: Listener, feed: Feed, handshake: HandshakeMode) -> Result<()> {
    let live = Rc::new(Cell::new(0usize));
    loop {
        let session = match accept_session::<linux_agent::Client, _>(
            &listener,
            &handshake,
            Protocol::new(
                LINUX_PROTOCOL.id,
                LINUX_PROTOCOL.major,
                LINUX_PROTOCOL.minor,
                LINUX_PROTOCOL.patch,
            ),
            AgentImpl { feed: feed.clone() },
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                tracing::error!("accept_session failed: {e:?}");
                continue;
            }
        };
        tracing::info!(peer_version = ?session.peer_version(), "host session accepted");
        live.set(live.get() + 1);
        let live = live.clone();
        compio::runtime::spawn(async move {
            if let Err(e) = session.wait().await {
                tracing::warn!("rpc session ended: {e:?}");
            }
            live.set(live.get() - 1);
            if live.get() == 0 {
                tracing::info!("last host session ended, exiting");
                std::process::exit(0);
            }
        })
        .detach();
    }
}
