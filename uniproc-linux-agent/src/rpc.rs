//! capnp RPC front-end, mirroring uniproc-windows-agent's src/rpc:
//! `Endpoint` + `accept_session` + a `linux_agent::Server` impl.
//!
//! One listener: vsock port 5000, which the host (Windows) dials in from
//! outside the VM. There used to be a second one on a uds socket for in-guest
//! clients, but nothing consumes it - anything running inside the VM can read
//! the same data straight from /proc.

use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use ogurpchik::auth::handshake::{HandshakeMode, SchemaId};
use ogurpchik::endpoint::Endpoint;
use ogurpchik::net::Listener;
use ogurpchik::net::vsock::VsockTarget;
use ogurpchik::rpc::accept_session;
use uniproc_protocol::linux_capnp::{self, EnvironmentKind, linux_agent};
use uniproc_protocol::meta_capnp::{ResponseStatus, response_meta};
use uniproc_protocol::{LINUX_SCHEMA_ID, WSL_AGENT_VSOCK_PORT};

use crate::bpf::BpfAgent;
use crate::report::{
    LinuxDockerContainerInfo, LinuxEnvironmentInfo, LinuxEnvironmentKind, MachineStats,
    ProcessStats,
};

#[derive(Clone)]
struct AgentImpl {
    agent: Arc<Mutex<BpfAgent<'static>>>,
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
        _: linux_agent::GetReportParams,
        mut results: linux_agent::GetReportResults,
    ) -> std::result::Result<(), capnp::Error> {
        let (processes, environments, docker_containers, machine) = self
            .agent
            .lock()
            .unwrap()
            .collect()
            .map_err(|e| capnp::Error::failed(format!("collect failed: {e:#}")))?;
        let mut out = results.get();
        uncacheable(out.reborrow().init_meta());
        build_report(
            &machine,
            &processes,
            &environments,
            &docker_containers,
            out.init_report(),
        );
        Ok(())
    }
}

/// Every report is a fresh sample, so there is never a payload worth an etag.
fn uncacheable(mut meta: response_meta::Builder) {
    meta.set_etag(0);
    meta.set_status(ResponseStatus::Ok);
}

pub async fn run(agent: Arc<Mutex<BpfAgent<'static>>>, secret: Vec<u8>) -> Result<()> {
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

    serve_loop(vsock_listener, agent, handshake).await
}

async fn serve_loop(
    listener: Listener,
    agent: Arc<Mutex<BpfAgent<'static>>>,
    handshake: HandshakeMode,
) -> Result<()> {
    loop {
        let session = match accept_session::<linux_agent::Client, _>(
            &listener,
            &handshake,
            SchemaId(LINUX_SCHEMA_ID),
            AgentImpl {
                agent: agent.clone(),
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
        // A stalled session must not hold the next client in its handshake.
        compio::runtime::spawn(async move {
            if let Err(e) = session.wait().await {
                tracing::warn!("rpc session ended: {e:?}");
            }
        })
        .detach();
    }
}

fn build_report(
    machine: &MachineStats,
    processes: &[ProcessStats],
    environments: &[LinuxEnvironmentInfo],
    docker_containers: &[LinuxDockerContainerInfo],
    mut out: linux_capnp::report::Builder,
) {
    build_machine_stats(machine, out.reborrow().init_machine());

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
