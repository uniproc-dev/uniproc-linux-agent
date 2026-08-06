use crate::bpf::BpfAgent;
use ogurpchik::transport::stream::adapters::vsock::{VsockAddr, VsockTransport};
use std::sync::{Arc, Mutex};
use futures::try_join;
use ogurpchik::discovery::Scope;
use ogurpchik::high::node::Node;
use ogurpchik::high::service_handler::ServiceHandler;
use ogurpchik::transport::stream::adapters::uds::UdsTransport;
use tracing_subscriber::filter::LevelFilter;
use uniproc_protocol::{services, LinuxCodec, ArchivedLinuxRequest, LinuxResponse};

mod batch_lookup;
mod bpf;
mod environment_resolver;
mod iter_gc;
mod name_cache;
mod process_metrics_state;
mod seed;

#[derive(Clone)]
struct GuestHandler {
    agent: Arc<Mutex<BpfAgent>>,
}

impl ServiceHandler<LinuxCodec> for GuestHandler {
    async fn on_request<'a>(&self, req: &ArchivedLinuxRequest) -> anyhow::Result<LinuxResponse> {
        match req {
            ArchivedLinuxRequest::GetReport => {
                let (processes, environments, docker_containers, machine) =
                    self.agent.lock().unwrap().collect()?;
                Ok(LinuxResponse::Report(uniproc_protocol::LinuxReport {
                    machine,
                    processes,
                    environments,
                    docker_containers,
                }))
            }
            ArchivedLinuxRequest::Ping => Ok(LinuxResponse::Pong),
        }
    }
}

#[compio::main]
async fn main() -> anyhow::Result<()> {
    unsafe {
        libc::mallopt(libc::M_ARENA_MAX, 1);
        libc::mallopt(libc::M_TRIM_THRESHOLD, 131072);
        libc::mallopt(libc::M_MMAP_THRESHOLD, 131072);
        libc::malloc_trim(0);
    }

    tracing_subscriber::fmt()
        .with_max_level(LevelFilter::DEBUG)
        .init();

    let agent = Arc::new(Mutex::new(BpfAgent::init()?));

    let (_vsock_guard, _uds_guard) = try_join!(
        Node::new()?
            .serve::<LinuxCodec, _, _>(
                VsockTransport::server(VsockAddr::SelfManaged, 5000),
                GuestHandler { agent: agent.clone() },
            )
            .publish(services::LINUX_AGENT)
            .start(),

        Node::new()?
            .scope(Scope::Internal)?
            .serve::<LinuxCodec, _, _>(
                UdsTransport::temp("uniproc"),
                GuestHandler { agent },
            )
            .publish("uniproc")
            .start(),
    )?;


    futures::future::pending::<()>().await;
    Ok(())
}
