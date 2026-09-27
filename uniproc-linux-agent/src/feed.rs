use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};

use libbpf_rs::OpenObject;
use uniproc_agent_kit::{Cadence, Epoch, Monitor, Tagged, Versioned};

use crate::bpf::BpfAgent;
use crate::report::Report;

/// The report the collector published last, or why its last collect failed.
#[derive(Clone)]
pub struct Latest(Arc<Mutex<State>>);

struct State {
    report: Versioned<Arc<Report>>,
    failure: Option<String>,
}

impl Latest {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(State {
            report: Versioned::new(Epoch::new(), Arc::new(Report::default())),
            failure: None,
        })))
    }

    pub fn get(&self) -> Result<Tagged<Arc<Report>>, String> {
        let state = self.0.lock().unwrap();
        match &state.failure {
            Some(failure) => Err(failure.clone()),
            None => Ok(state.report.get().clone()),
        }
    }

    fn publish(&self, collected: anyhow::Result<Report>) {
        let mut state = self.0.lock().unwrap();
        match collected {
            Ok(report) => {
                state.report.set(Arc::new(report));
                state.failure = None;
            }
            Err(e) => {
                tracing::warn!("collect failed: {e:#}");
                state.failure = Some(format!("{e:#}"));
            }
        }
    }
}

/// Loads the BPF programs on a collector thread and returns once its first report is in.
pub fn start() -> anyhow::Result<(Monitor, Latest)> {
    let latest = Latest::new();
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
            move |collected| latest.publish(collected)
        },
    )?;
    Ok((monitor, latest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(total_kb: u64) -> Report {
        let mut report = Report::default();
        report.machine.total_kb = total_kb;
        report
    }

    #[test]
    fn the_same_report_again_keeps_its_etag() {
        let latest = Latest::new();
        latest.publish(Ok(report(1)));
        let first = latest.get().unwrap().etag;
        latest.publish(Ok(report(1)));
        assert_eq!(latest.get().unwrap().etag, first);
    }

    #[test]
    fn a_different_report_moves_the_etag() {
        let latest = Latest::new();
        latest.publish(Ok(report(1)));
        let first = latest.get().unwrap().etag;
        latest.publish(Ok(report(2)));
        let second = latest.get().unwrap();
        assert_ne!(second.etag, first);
        assert_eq!(second.value.machine.total_kb, 2);
    }

    #[test]
    fn a_failed_collect_is_served_until_the_next_good_one() {
        let latest = Latest::new();
        latest.publish(Ok(report(1)));
        latest.publish(Err(anyhow::anyhow!("map gone")));
        assert_eq!(latest.get().unwrap_err(), "map gone");
        latest.publish(Ok(report(2)));
        assert_eq!(latest.get().unwrap().value.machine.total_kb, 2);
    }
}
