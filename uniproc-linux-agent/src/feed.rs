use std::mem::MaybeUninit;

use libbpf_rs::OpenObject;
use uniproc_agent_kit::{Cadence, Latest, Monitor};

use crate::bpf::BpfAgent;
use crate::report::Report;

/// Loads the BPF programs on a collector thread and returns once its first report is in.
pub fn start() -> anyhow::Result<(Monitor, Latest<Report>)> {
    let latest = Latest::<Report>::default();
    let monitor = Monitor::start(
        "collector",
        Cadence::default(),
        || {
            let open_object = Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));
            let mut agent = BpfAgent::init(open_object)?;
            Ok(move || agent.collect())
        },
        {
            let latest = latest.clone();
            move |collected: anyhow::Result<Report>| {
                if let Err(e) = &collected {
                    tracing::warn!("collect failed: {e:#}");
                }
                latest.publish(collected)
            }
        },
    )?;
    Ok((monitor, latest))
}
