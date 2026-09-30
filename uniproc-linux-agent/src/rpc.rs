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
use futures::StreamExt;
use futures::future::{AbortHandle, Abortable};
use ogurpchik::auth::handshake::{HandshakeMode, Protocol};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::net::Listener;
use ogurpchik::net::vsock::VsockTarget;
use ogurpchik::rpc::accept_session;
use uniproc_agent_kit::{Busy, Tagged, Watch};
use uniproc_protocol::linux_capnp::{agent_listener, linux_agent, lists_update, unit_watcher, watch_handle};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::{LINUX_PROTOCOL, WSL_AGENT_VSOCK_PORT};

use crate::commands;
use crate::feed::Feed;
use crate::model::{Key, Passports, Snapshot, States};
use crate::units::{Unit, UnitStatus, Units};
use crate::wire::{self, Wanted};

const MIN_INTERVAL: Duration = Duration::from_millis(100);
const MAX_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct AgentImpl {
    feed: Feed,
    units: Units,
}

impl AgentImpl {
    async fn unit_job(&self, name: capnp::text::Reader<'_>, method: &'static str) -> std::result::Result<u32, capnp::Error> {
        let name = name.to_str()?.to_owned();
        Ok(match self.units.command(name, method) {
            Ok(answer) => answer.await.unwrap_or(libc::EIO as u32),
            Err(Busy) => libc::EBUSY as u32,
        })
    }

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
        let mut budget = wire::CMDLINE_BUDGET;
        for (i, passport) in passports.values().enumerate() {
            wire::process_info(passport, list.reborrow().get(i as u32), &mut budget);
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
            push(self.feed.clone(), self.units.clone(), interval, wanted, listener),
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

    async fn get_units(
        self: Rc<Self>,
        params: linux_agent::GetUnitsParams,
        mut results: linux_agent::GetUnitsResults,
    ) -> std::result::Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let units = self.units.list();
        let mut out = results.get();
        if !answer(&units, if_none_match, out.reborrow().init_meta()) {
            return Ok(());
        }
        wire::units(&units.value, out.init_units(units.value.len() as u32));
        Ok(())
    }

    async fn unit_start(
        self: Rc<Self>,
        params: linux_agent::UnitStartParams,
        mut results: linux_agent::UnitStartResults,
    ) -> std::result::Result<(), capnp::Error> {
        let code = self.unit_job(params.get()?.get_name()?, "StartUnit").await?;
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn unit_stop(
        self: Rc<Self>,
        params: linux_agent::UnitStopParams,
        mut results: linux_agent::UnitStopResults,
    ) -> std::result::Result<(), capnp::Error> {
        let code = self.unit_job(params.get()?.get_name()?, "StopUnit").await?;
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn unit_restart(
        self: Rc<Self>,
        params: linux_agent::UnitRestartParams,
        mut results: linux_agent::UnitRestartResults,
    ) -> std::result::Result<(), capnp::Error> {
        let code = self.unit_job(params.get()?.get_name()?, "RestartUnit").await?;
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn unit_reload(
        self: Rc<Self>,
        params: linux_agent::UnitReloadParams,
        mut results: linux_agent::UnitReloadResults,
    ) -> std::result::Result<(), capnp::Error> {
        let code = self.unit_job(params.get()?.get_name()?, "ReloadUnit").await?;
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_code(code);
        Ok(())
    }

    async fn watch_unit(
        self: Rc<Self>,
        params: linux_agent::WatchUnitParams,
        mut results: linux_agent::WatchUnitResults,
    ) -> std::result::Result<(), capnp::Error> {
        let params = params.get()?;
        let name = params.get_name()?.to_str()?.to_owned();
        let watcher = params.get_watcher()?;
        let (abort, registration) = AbortHandle::new_pair();
        compio::runtime::spawn(Abortable::new(follow_unit(self.units.watch(name), watcher), registration)).detach();
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        out.set_handle(capnp_rpc::new_client(WatchHandleImpl(abort)));
        Ok(())
    }
}

async fn follow_unit(mut statuses: Watch<UnitStatus>, watcher: unit_watcher::Client) {
    while let Some(status) = statuses.next().await {
        let mut request = watcher.changed_request();
        request.get().init_meta();
        wire::unit_status(&status, request.get().init_status());
        if let Err(e) = request.send().promise.await {
            tracing::info!("unit watch ended by its watcher: {e}");
            return;
        }
    }
    let mut request = watcher.ended_request();
    request.get().init_meta();
    let _ = request.send().promise.await;
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
    units_etag: u64,
}

impl Sent {
    fn of(snapshot: &Snapshot, units: &Tagged<Arc<Vec<Unit>>>) -> Self {
        Self {
            number: snapshot.number,
            passports: snapshot.passports.clone(),
            states: snapshot.states.clone(),
            environments_etag: snapshot.environments.etag,
            units_etag: units.etag,
        }
    }
}

async fn push(feed: Feed, units: Units, interval: Duration, wanted: Wanted, listener: agent_listener::Client) {
    let _lease = feed.lease(interval);
    let mut generation = feed.fresh.generation();
    let mut sent: Option<Sent> = None;
    loop {
        if let Ok(current) = feed.latest.get()
            && sent.as_ref().is_none_or(|s| s.number != current.value.number)
        {
            let snapshot = &current.value;
            let units = units.list();
            let started = Instant::now();
            let mut request = listener.update_request();
            let mut out = request.get();
            out.reborrow().init_meta();
            lists(sent.as_ref(), snapshot, &units, out.reborrow().init_lists());
            wire::columns(snapshot, wanted, out.reborrow().init_processes());
            wire::machine(snapshot, wanted, out.init_machine());
            if let Err(e) = request.send().promise.await {
                tracing::info!("watch ended by its listener: {e}");
                return;
            }
            sent = Some(Sent::of(snapshot, &units));
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

fn lists(sent: Option<&Sent>, snapshot: &Snapshot, units: &Tagged<Arc<Vec<Unit>>>, mut out: lists_update::Builder) {
    out.set_passport_etag(snapshot.passports.etag);
    out.set_states_etag(snapshot.states.etag);
    out.set_environments_etag(snapshot.environments.etag);
    out.set_units_etag(units.etag);

    let passports = &snapshot.passports.value;
    let mut budget = wire::CMDLINE_BUDGET;
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
                wire::process_info(passport, list.reborrow().get(i as u32), &mut budget);
            }
        }
        None => {
            let mut list = out.reborrow().init_passports().init_full(passports.len() as u32);
            for (i, passport) in passports.values().enumerate() {
                wire::process_info(passport, list.reborrow().get(i as u32), &mut budget);
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
            out.reborrow().init_environments().set_unchanged(())
        }
        _ => {
            let e = &snapshot.environments.value;
            let mut full = out.reborrow().init_environments().init_full();
            wire::environments(e, full.reborrow().init_environments(e.environments.len() as u32));
            wire::docker_containers(e, full.init_docker_containers(e.docker_containers.len() as u32));
        }
    }

    match sent {
        Some(s) if s.units_etag == units.etag => out.init_units().set_unchanged(()),
        _ => wire::units(&units.value, out.init_units().init_full(units.value.len() as u32)),
    }
}

fn uncacheable(mut meta: response_meta::Builder) {
    meta.set_etag(0);
    meta.set_status(ResponseStatus::Ok);
}

pub async fn run(feed: Feed, units: Units, secret: Vec<u8>) -> Result<()> {
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
    let vsock_listener = match vsock.listen().await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!("failed to bind vsock port {WSL_AGENT_VSOCK_PORT}: {e:?}");
            std::process::exit(EXIT_PORT_TAKEN);
        }
    };

    tracing::info!(%vsock, "listening");

    serve_loop(vsock_listener, AgentImpl { feed, units }, handshake).await
}

/// Exit status when the vsock port is already bound.
pub const EXIT_PORT_TAKEN: i32 = 3;
/// Exit status when no host session came up in time, or handshakes kept failing.
pub const EXIT_NO_HOST: i32 = 2;

const NO_HOST_FOR: Duration = Duration::from_secs(30);
const HANDSHAKE_FAILURES: u32 = 5;

/// How many host sessions are live, since when none has been, and how many handshakes failed in a row.
struct Presence {
    live: Cell<usize>,
    idle_since: Cell<Option<Instant>>,
    failures: Cell<u32>,
}

impl Presence {
    fn new(now: Instant) -> Self {
        Self {
            live: Cell::new(0),
            idle_since: Cell::new(Some(now)),
            failures: Cell::new(0),
        }
    }

    fn accepted(&self) {
        self.live.set(self.live.get() + 1);
        self.idle_since.set(None);
        self.failures.set(0);
    }

    /// True when it was the last live session.
    fn ended(&self) -> bool {
        self.live.set(self.live.get() - 1);
        self.live.get() == 0
    }

    /// True once handshakes failed too many times in a row.
    fn failed(&self) -> bool {
        self.failures.set(self.failures.get() + 1);
        self.failures.get() >= HANDSHAKE_FAILURES
    }

    fn deserted(&self, now: Instant) -> bool {
        self.idle_since
            .get()
            .is_some_and(|since| now.duration_since(since) >= NO_HOST_FOR)
    }
}

async fn serve_loop(listener: Listener, agent: AgentImpl, handshake: HandshakeMode) -> Result<()> {
    let presence = Rc::new(Presence::new(Instant::now()));
    compio::runtime::spawn({
        let presence = presence.clone();
        async move {
            loop {
                compio::time::sleep(Duration::from_secs(1)).await;
                if presence.deserted(Instant::now()) {
                    tracing::error!("no host session for {NO_HOST_FOR:?}, exiting");
                    std::process::exit(EXIT_NO_HOST);
                }
            }
        }
    })
    .detach();
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
            agent.clone(),
        )
        .await
        {
            Ok(session) => session,
            Err(e) => {
                tracing::error!("accept_session failed: {e:?}");
                if presence.failed() {
                    tracing::error!("{HANDSHAKE_FAILURES} handshakes failed in a row, exiting");
                    std::process::exit(EXIT_NO_HOST);
                }
                continue;
            }
        };
        tracing::info!(peer_version = ?session.peer_version(), "host session accepted");
        presence.accepted();
        let presence = presence.clone();
        compio::runtime::spawn(async move {
            if let Err(e) = session.wait().await {
                tracing::warn!("rpc session ended: {e:?}");
            }
            if presence.ended() {
                tracing::info!("last host session ended, exiting");
                std::process::exit(0);
            }
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use uniproc_agent_kit::{Epoch, Versioned};
    use uniproc_protocol::linux_capnp::{
        MachineMetric, ProcessMetric, UnitActiveState, UnitFileState, UnitJob, UnitLoadState, lists_update,
    };

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
        units: String,
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
            let units = match lists.get_units().which()? {
                lists_update::units::Unchanged(()) => "unchanged".to_string(),
                lists_update::units::Full(full) => format!(
                    "full:{}",
                    full?.iter().map(|u| u.get_name().unwrap().to_string().unwrap()).collect::<Vec<_>>().join(",")
                ),
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
                units,
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
        agent_with(feed, &Units::detached().0)
    }

    fn agent_with(feed: &Feed, units: &Units) -> linux_agent::Client {
        capnp_rpc::new_client(AgentImpl {
            feed: feed.clone(),
            units: units.clone(),
        })
    }

    fn unit(name: &str, active: UnitActiveState) -> Unit {
        Unit {
            name: name.into(),
            description: String::new(),
            load: UnitLoadState::Loaded,
            active,
            sub: String::new(),
            file_state: UnitFileState::Enabled,
            file: String::new(),
            main: (active == UnitActiveState::Active).then(|| key(10)),
            job: UnitJob::None,
        }
    }

    #[compio::test]
    async fn get_units_is_conditional_and_names_main_processes_globally() {
        let (units, _board) = Units::detached();
        units.latest.set(vec![unit("ssh.service", UnitActiveState::Active)]);
        let agent = agent_with(&Feed::without_collector(), &units);

        let response = agent.get_units_request().send().promise.await.unwrap();
        let answer = response.get().unwrap();
        let etag = answer.get_meta().unwrap().get_etag();
        let ssh = answer.get_units().unwrap().get(0);
        assert_eq!(ssh.get_name().unwrap().to_str().unwrap(), "ssh.service");
        assert_eq!(ssh.get_active_state().unwrap(), UnitActiveState::Active);
        assert_eq!((ssh.get_main_pid(), ssh.get_main_sequence_number()), (10, key(10).sequence_number));

        units.latest.set(vec![unit("ssh.service", UnitActiveState::Active)]);
        let mut request = agent.get_units_request();
        request.get().init_meta().set_if_none_match(etag);
        let response = request.send().promise.await.unwrap();
        assert_eq!(response.get().unwrap().get_meta().unwrap().get_status().unwrap(), ResponseStatus::NotModified);

        units.latest.set(vec![unit("ssh.service", UnitActiveState::Inactive)]);
        let mut request = agent.get_units_request();
        request.get().init_meta().set_if_none_match(etag);
        let response = request.send().promise.await.unwrap();
        let ssh = response.get().unwrap().get_units().unwrap().get(0);
        assert_eq!(ssh.get_active_state().unwrap(), UnitActiveState::Inactive);
        assert_eq!(ssh.get_main_pid(), 0);
    }

    #[compio::test]
    async fn long_command_lines_share_one_budget_per_message() {
        let feed = Feed::without_collector();
        let arg = "x".repeat(crate::procfs::CMDLINE_MAX);
        let passports: Passports = (1..=400)
            .map(|pid| {
                let mut passport = Passport::clone(&passport(pid));
                passport.cmdline = vec![arg.clone()];
                (key(pid), Arc::new(passport))
            })
            .collect();
        let mut snapshot = Snapshot::empty();
        snapshot.passports.value = Arc::new(passports);
        feed.latest.replace(snapshot);

        let response = agent(&feed).get_processes_request().send().promise.await.unwrap();
        let processes = response.get().unwrap().get_processes().unwrap();
        assert_eq!(processes.len(), 400);
        let carried: usize = processes
            .iter()
            .flat_map(|p| p.get_cmdline().unwrap().iter().map(|a| a.unwrap().len()).collect::<Vec<_>>())
            .sum();
        assert_eq!(carried, wire::CMDLINE_BUDGET);
        assert_eq!(processes.get(0).get_cmdline().unwrap().get(0).unwrap().len(), arg.len());
        assert_eq!(processes.get(399).get_cmdline().unwrap().len(), 0);
    }

    #[compio::test]
    async fn a_unit_command_without_systemd_is_not_connected() {
        let agent = agent(&Feed::without_collector());
        let mut request = agent.unit_restart_request();
        request.get().set_name("ssh.service");
        let code = request.send().promise.await.unwrap().get().unwrap().get_code();
        assert_eq!(code, libc::ENOTCONN as u32);
    }

    struct UnitRecorder {
        seen: Rc<RefCell<Vec<(UnitActiveState, u32)>>>,
        ended: Rc<Cell<bool>>,
    }

    impl unit_watcher::Server for UnitRecorder {
        async fn changed(
            self: Rc<Self>,
            params: unit_watcher::ChangedParams,
            _: unit_watcher::ChangedResults,
        ) -> std::result::Result<(), capnp::Error> {
            let status = params.get()?.get_status()?;
            self.seen.borrow_mut().push((status.get_active_state()?, status.get_main_pid()));
            Ok(())
        }

        async fn ended(
            self: Rc<Self>,
            _: unit_watcher::EndedParams,
            _: unit_watcher::EndedResults,
        ) -> std::result::Result<(), capnp::Error> {
            self.ended.set(true);
            Ok(())
        }
    }

    fn status(active: UnitActiveState, main: Option<Key>) -> UnitStatus {
        UnitStatus {
            load: UnitLoadState::Loaded,
            active,
            sub: String::new(),
            main,
            job: UnitJob::None,
            result: "success".into(),
            exec_main_code: 0,
            exec_main_status: 0,
            restarts: 0,
        }
    }

    #[compio::test]
    async fn a_unit_watch_streams_every_status_then_ends_with_the_unit() {
        let (units, mut board) = Units::detached();
        let agent = agent_with(&Feed::without_collector(), &units);
        let seen = Rc::new(RefCell::new(Vec::new()));
        let ended = Rc::new(Cell::new(false));

        let mut request = agent.watch_unit_request();
        request.get().set_name("ssh.service");
        request.get().set_watcher(capnp_rpc::new_client(UnitRecorder {
            seen: seen.clone(),
            ended: ended.clone(),
        }));
        let _response = request.send().promise.await.unwrap();

        let name = "ssh.service".to_string();
        board.take_requests(|n| n == "ssh.service");
        board.publish(&name, status(UnitActiveState::Activating, None));
        board.publish(&name, status(UnitActiveState::Active, Some(key(10))));
        until(|| seen.borrow().len() == 2).await;
        assert_eq!(
            *seen.borrow(),
            [(UnitActiveState::Activating, 0), (UnitActiveState::Active, 10)]
        );

        board.end(&name);
        until(|| ended.get()).await;
    }

    #[compio::test]
    async fn a_watch_carries_the_units_once_and_then_says_unchanged() {
        let feed = Feed::without_collector();
        let (units, _board) = Units::detached();
        units.latest.set(vec![unit("ssh.service", UnitActiveState::Active)]);
        let mut lists = Lists::new();
        lists.publish(&feed, &[(10, 0)]);
        let seen = Rc::new(RefCell::new(Vec::new()));

        let mut request = agent_with(&feed, &units).watch_request();
        request.get().init_spec().set_interval_ms(100);
        request.get().set_listener(capnp_rpc::new_client(Recorder(seen.clone())));
        let _response = request.send().promise.await.unwrap();
        until(|| seen.borrow().len() == 1).await;
        assert_eq!(seen.borrow()[0].units, "full:ssh.service");

        lists.publish(&feed, &[(10, 0)]);
        until(|| seen.borrow().len() == 2).await;
        assert_eq!(seen.borrow()[1].units, "unchanged");

        units.latest.set(vec![unit("ssh.service", UnitActiveState::Failed)]);
        lists.publish(&feed, &[(10, 0)]);
        until(|| seen.borrow().len() == 3).await;
        assert_eq!(seen.borrow()[2].units, "full:ssh.service");
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

    #[test]
    fn no_host_for_a_while_or_repeated_failed_handshakes_end_the_agent() {
        let start = Instant::now();
        let presence = Presence::new(start);
        assert!(!presence.deserted(start + NO_HOST_FOR - Duration::from_millis(1)));
        assert!(presence.deserted(start + NO_HOST_FOR));

        let presence = Presence::new(start);
        presence.accepted();
        assert!(!presence.deserted(start + NO_HOST_FOR * 10));
        assert!(presence.ended());

        let presence = Presence::new(start);
        for _ in 1..HANDSHAKE_FAILURES {
            assert!(!presence.failed());
        }
        presence.accepted();
        for _ in 1..HANDSHAKE_FAILURES {
            assert!(!presence.failed());
        }
        assert!(presence.failed());
    }
}
