//! Manual end-to-end check against a running agent:
//!   sudo ./target/debug/uniproc-linux-agent &
//!   sudo -E cargo run --example rpc_client
//!
//! Connects over the conventional uds endpoint, calls ping and getReport.

use ogurpchik::auth::handshake::HandshakeMode;
use ogurpchik::endpoint::Endpoint;
use ogurpchik::rpc::connect_session;
use uniproc_protocol::linux_capnp::linux_agent;

struct ClientStub;
impl linux_agent::Server for ClientStub {}

fn main() -> anyhow::Result<()> {
    compio::runtime::Runtime::new()?.block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let endpoint = Endpoint::for_service("uniproc", "linux-agent")
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let session = connect_session::<linux_agent::Client, _>(
        &endpoint,
        &HandshakeMode::version_only(),
        ClientStub,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let client = session.remote().clone();

    client.ping_request().send().promise.await?;
    println!("ping: ok");

    let reply = client.get_report_request().send().promise.await?;
    let report = reply.get()?.get_report()?;
    let machine = report.get_machine()?;
    let processes = report.get_processes()?;
    println!(
        "getReport: {} processes, {} environments, {} docker containers, mem used {} kb, busy {} ns",
        processes.len(),
        report.get_environments()?.len(),
        report.get_docker_containers()?.len(),
        machine.get_used_kb(),
        machine.get_busy_ns(),
    );

    for p in processes.iter().take(8) {
        println!(
            "    pid={:<6} name={:<20} cpu={:.1}% rss={} kb",
            p.get_global_pid(),
            p.get_name()?.to_str()?,
            p.get_cpu_percent(),
            p.get_rss_kb(),
        );
    }

    Ok(())
}
