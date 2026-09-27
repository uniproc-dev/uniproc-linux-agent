//! capnp RPC front-end, mirroring uniproc-windows-agent's src/rpc:
//! `Endpoint` + `accept_session` + a `linux_agent::Server` impl.
//!
//! One listener: vsock port 5000, which the host (Windows) dials in from
//! outside the VM. There used to be a second one on a uds socket for in-guest
//! clients, but nothing consumes it - anything running inside the VM can read
//! the same data straight from /proc.

use std::cell::Cell;
use std::rc::Rc;

use anyhow::Result;
use ogurpchik::auth::handshake::{HandshakeMode, Protocol};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::net::Listener;
use ogurpchik::net::vsock::VsockTarget;
use ogurpchik::rpc::accept_session;
use uniproc_protocol::linux_capnp::{self, EnvironmentKind, linux_agent};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::{LINUX_PROTOCOL, WSL_AGENT_VSOCK_PORT};

use uniproc_agent_kit::Latest;

use crate::report::{LinuxEnvironmentKind, MachineStats, Report};

#[derive(Clone)]
struct AgentImpl {
    latest: Latest<Report>,
}

impl linux_agent::Server for AgentImpl {
    async fn ping(
        self: Rc<Self>,
        _: linux_agent::PingParams,
        mut results: linux_agent::PingResults,
    ) -> std::result::Result<(), capnp::Error> {
        uncacheable(results.get().init_meta());
        Ok(())
    }

    async fn get_report(
        self: Rc<Self>,
        params: linux_agent::GetReportParams,
        mut results: linux_agent::GetReportResults,
    ) -> std::result::Result<(), capnp::Error> {
        let if_none_match = params.get()?.get_meta()?.get_if_none_match();
        let current = self
            .latest
            .get()
            .map_err(|e| capnp::Error::failed(format!("collect failed: {e}")))?;
        let mut out = results.get();
        let mut meta = out.reborrow().init_meta();
        meta.set_etag(current.etag);
        if current.unchanged_since(if_none_match) {
            meta.set_status(ResponseStatus::NotModified);
            return Ok(());
        }
        meta.set_status(ResponseStatus::Ok);
        build_report(&current.value, out.init_report());
        Ok(())
    }
}

fn uncacheable(mut meta: response_meta::Builder) {
    meta.set_etag(0);
    meta.set_status(ResponseStatus::Ok);
}

pub async fn run(latest: Latest<Report>, secret: Vec<u8>) -> Result<()> {
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

    serve_loop(vsock_listener, latest, handshake).await
}

async fn serve_loop(
    listener: Listener,
    latest: Latest<Report>,
    handshake: HandshakeMode,
) -> Result<()> {
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
            AgentImpl {
                latest: latest.clone(),
            },
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

fn build_report(report: &Report, mut out: linux_capnp::report::Builder) {
    build_machine_stats(&report.machine, out.reborrow().init_machine());

    let processes = &report.processes;
    let mut list = out.reborrow().init_processes(processes.len() as u32);
    for (i, p) in processes.iter().enumerate() {
        let mut dst = list.reborrow().get(i as u32);
        dst.set_global_pid(p.global_pid);
        dst.set_local_pid(p.local_pid);
        dst.set_mnt_ns(p.mnt_ns);
        dst.set_pid_ns(p.pid_ns);
        dst.set_name(process_name(&p.name));

        dst.set_cpu_percent(p.cpu_percent);
        dst.set_rss_kb(p.rss_kb);
        dst.set_last_active_ns(p.last_active_ns);

        dst.set_vsock_rx_bytes(p.vsock_rx_bytes);
        dst.set_vsock_tx_bytes(p.vsock_tx_bytes);
        dst.set_p9_rx_bytes(p.p9_rx_bytes);
        dst.set_p9_tx_bytes(p.p9_tx_bytes);

        dst.set_tcp_tx_lo_bytes(p.tcp_tx_lo_bytes);
        dst.set_tcp_rx_lo_bytes(p.tcp_rx_lo_bytes);
        dst.set_tcp_tx_remote_bytes(p.tcp_tx_remote_bytes);
        dst.set_tcp_rx_remote_bytes(p.tcp_rx_remote_bytes);
        dst.set_udp_tx_lo_bytes(p.udp_tx_lo_bytes);
        dst.set_udp_rx_lo_bytes(p.udp_rx_lo_bytes);
        dst.set_udp_tx_remote_bytes(p.udp_tx_remote_bytes);
        dst.set_udp_rx_remote_bytes(p.udp_rx_remote_bytes);
        dst.set_uds_tx_bytes(p.uds_tx_bytes);
        dst.set_uds_rx_bytes(p.uds_rx_bytes);

        dst.set_disk_read_bytes(p.disk_read_bytes);
        dst.set_disk_write_bytes(p.disk_write_bytes);
        dst.set_disk_read_iops(p.disk_read_iops);
        dst.set_disk_write_iops(p.disk_write_iops);

        dst.set_pipe_read_bytes(p.pipe_read_bytes);
        dst.set_pipe_write_bytes(p.pipe_write_bytes);
        dst.set_sendfile_bytes(p.sendfile_bytes);
    }

    let environments = &report.environments;
    let mut list = out
        .reborrow()
        .init_environments(environments.len() as u32);
    for (i, e) in environments.iter().enumerate() {
        let mut dst = list.reborrow().get(i as u32);
        dst.set_mnt_ns(e.mnt_ns);
        dst.set_pid_ns(e.pid_ns);
        match &e.kind {
            LinuxEnvironmentKind::Unknown => {
                dst.set_kind(EnvironmentKind::Unknown);
            }
            LinuxEnvironmentKind::CurrentDistro { name } => {
                dst.set_kind(EnvironmentKind::CurrentDistro);
                dst.set_name(name);
            }
            LinuxEnvironmentKind::DockerContainer { id } => {
                dst.set_kind(EnvironmentKind::DockerContainer);
                dst.set_name(id);
            }
            LinuxEnvironmentKind::UnknownExternalNamespace => {
                dst.set_kind(EnvironmentKind::UnknownExternalNamespace);
            }
        }
    }

    let docker_containers = &report.docker_containers;
    let mut list = out
        .reborrow()
        .init_docker_containers(docker_containers.len() as u32);
    for (i, c) in docker_containers.iter().enumerate() {
        let mut dst = list.reborrow().get(i as u32);
        dst.set_id(c.id.as_str());
        dst.set_mnt_ns(c.mnt_ns);
        dst.set_pid_ns(c.pid_ns);
        dst.set_api_version(c.api_version.as_str());
        dst.set_raw_json(c.raw_json.as_str());
    }
}

fn build_machine_stats(m: &MachineStats, mut out: linux_capnp::machine_stats::Builder) {
    out.set_total_kb(m.total_kb);
    out.set_free_kb(m.free_kb);
    out.set_available_kb(m.available_kb);
    out.set_used_kb(m.used_kb);
    out.set_cached_kb(m.cached_kb);

    out.set_busy_ns(m.busy_ns);
    out.set_last_tsc(m.last_tsc);

    out.set_vsock_rx_bytes(m.vsock_rx_bytes);
    out.set_vsock_tx_bytes(m.vsock_tx_bytes);
    out.set_p9_rx_bytes(m.p9_rx_bytes);
    out.set_p9_tx_bytes(m.p9_tx_bytes);

    out.set_tcp_tx_lo_bytes(m.tcp_tx_lo_bytes);
    out.set_tcp_rx_lo_bytes(m.tcp_rx_lo_bytes);
    out.set_tcp_tx_remote_bytes(m.tcp_tx_remote_bytes);
    out.set_tcp_rx_remote_bytes(m.tcp_rx_remote_bytes);
    out.set_udp_tx_lo_bytes(m.udp_tx_lo_bytes);
    out.set_udp_rx_lo_bytes(m.udp_rx_lo_bytes);
    out.set_udp_tx_remote_bytes(m.udp_tx_remote_bytes);
    out.set_udp_rx_remote_bytes(m.udp_rx_remote_bytes);
    out.set_uds_tx_bytes(m.uds_tx_bytes);
    out.set_uds_rx_bytes(m.uds_rx_bytes);

    out.set_disk_read_bytes(m.disk_read_bytes);
    out.set_disk_write_bytes(m.disk_write_bytes);
    out.set_disk_read_iops(m.disk_read_iops);
    out.set_disk_write_iops(m.disk_write_iops);

    out.set_pipe_read_bytes(m.pipe_read_bytes);
    out.set_pipe_write_bytes(m.pipe_write_bytes);
    out.set_sendfile_bytes(m.sendfile_bytes);
    out.set_cpu_count(m.cpu_count);
}

/// Kernel task names are NUL-padded fixed buffers; expose the &str up to the
/// first NUL.
fn process_name(name: &[u8; 64]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    std::str::from_utf8(&name[..end]).unwrap_or("<invalid>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{LinuxDockerContainerInfo, LinuxEnvironmentInfo, ProcessStats};

    fn process(global_pid: u32, name: &str) -> ProcessStats {
        let mut padded = [0u8; 64];
        padded[..name.len()].copy_from_slice(name.as_bytes());
        ProcessStats {
            global_pid,
            local_pid: 1,
            mnt_ns: 10,
            pid_ns: 20,
            name: padded,
            cpu_percent: 12.5,
            rss_kb: 2048,
            last_active_ns: 3,
            vsock_rx_bytes: 4,
            vsock_tx_bytes: 5,
            p9_rx_bytes: 6,
            p9_tx_bytes: 7,
            tcp_tx_lo_bytes: 8,
            tcp_rx_lo_bytes: 9,
            tcp_tx_remote_bytes: 10,
            tcp_rx_remote_bytes: 11,
            udp_tx_lo_bytes: 12,
            udp_rx_lo_bytes: 13,
            udp_tx_remote_bytes: 14,
            udp_rx_remote_bytes: 15,
            uds_tx_bytes: 16,
            uds_rx_bytes: 17,
            disk_read_bytes: 18,
            disk_write_bytes: 19,
            disk_read_iops: 20,
            disk_write_iops: 21,
            pipe_read_bytes: 22,
            pipe_write_bytes: 23,
            sendfile_bytes: 24,
        }
    }

    fn round_trip(report: &Report) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut message = capnp::message::Builder::new_default();
        build_report(report, message.init_root());
        message
    }

    #[test]
    fn a_report_reads_back_as_it_was_built() {
        let mut report = Report::default();
        report.machine.total_kb = 16_000_000;
        report.machine.busy_ns = 42;
        report.machine.cpu_count = 16;
        report.processes.push(process(4242, "bash"));
        report.environments.push(LinuxEnvironmentInfo {
            mnt_ns: 10,
            pid_ns: 20,
            kind: LinuxEnvironmentKind::CurrentDistro {
                name: "Ubuntu 24.04.3 LTS".into(),
            },
        });
        report.environments.push(LinuxEnvironmentInfo {
            mnt_ns: 30,
            pid_ns: 40,
            kind: LinuxEnvironmentKind::UnknownExternalNamespace,
        });
        report.docker_containers.push(LinuxDockerContainerInfo {
            id: "abc123".into(),
            mnt_ns: 50,
            pid_ns: 60,
            api_version: "v1.43".into(),
            raw_json: "{}".into(),
        });

        let message = round_trip(&report);
        let read = message
            .get_root_as_reader::<linux_capnp::report::Reader>()
            .unwrap();

        let machine = read.get_machine().unwrap();
        assert_eq!(machine.get_total_kb(), 16_000_000);
        assert_eq!(machine.get_busy_ns(), 42);
        assert_eq!(machine.get_cpu_count(), 16);

        let processes = read.get_processes().unwrap();
        assert_eq!(processes.len(), 1);
        let p = processes.get(0);
        assert_eq!(p.get_global_pid(), 4242);
        assert_eq!(p.get_name().unwrap().to_str().unwrap(), "bash");
        assert_eq!(p.get_cpu_percent(), 12.5);
        assert_eq!(p.get_rss_kb(), 2048);
        assert_eq!(p.get_uds_rx_bytes(), 17);
        assert_eq!(p.get_sendfile_bytes(), 24);

        let environments = read.get_environments().unwrap();
        assert_eq!(environments.len(), 2);
        let distro = environments.get(0);
        assert_eq!(distro.get_kind().unwrap(), EnvironmentKind::CurrentDistro);
        assert_eq!(
            distro.get_name().unwrap().to_str().unwrap(),
            "Ubuntu 24.04.3 LTS"
        );
        assert_eq!(
            environments.get(1).get_kind().unwrap(),
            EnvironmentKind::UnknownExternalNamespace
        );

        let containers = read.get_docker_containers().unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers.get(0).get_id().unwrap().to_str().unwrap(), "abc123");
        assert_eq!(containers.get(0).get_pid_ns(), 60);
    }

    #[test]
    fn a_name_without_a_nul_is_taken_whole() {
        let name = [b'a'; 64];
        assert_eq!(process_name(&name).len(), 64);
    }
}
