use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libbpf_rs::OpenObject;
use uniproc_agent_kit::monitor::{self, Collector, Monitor, Waker, Why};
use uniproc_agent_kit::{Latest, Notify};

use crate::bpf::BpfAgent;
use crate::report::Report;

const IDLE_PERIOD: Duration = Duration::from_secs(1);
const SPACING: Duration = Duration::from_millis(50);

/// The collector's latest report, a signal for each new one, and the
/// intervals watchers want it at.
#[derive(Clone)]
pub struct Feed {
    pub latest: Latest<Report>,
    pub fresh: Arc<Notify>,
    schedule: Schedule,
}

impl Feed {
    /// Keeps the collector ticking at least every `interval` while the lease lives.
    pub fn lease(&self, interval: Duration) -> Lease {
        self.schedule.intervals.lock().unwrap().push(interval);
        self.schedule.waker.wake();
        Lease {
            schedule: self.schedule.clone(),
            interval,
        }
    }
}

#[derive(Clone)]
struct Schedule {
    intervals: Arc<Mutex<Vec<Duration>>>,
    waker: Waker,
}

impl Schedule {
    fn period(&self) -> Duration {
        let intervals = self.intervals.lock().unwrap();
        intervals.iter().copied().min().unwrap_or(IDLE_PERIOD)
    }
}

pub struct Lease {
    schedule: Schedule,
    interval: Duration,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut intervals = self.schedule.intervals.lock().unwrap();
        if let Some(i) = intervals.iter().position(|&d| d == self.interval) {
            intervals.swap_remove(i);
        }
    }
}

struct BpfCollector {
    agent: BpfAgent<'static>,
    latest: Latest<Report>,
    fresh: Arc<Notify>,
    schedule: Schedule,
}

impl Collector for BpfCollector {
    fn tick(&mut self, _: Why) -> Instant {
        let collected = self.agent.collect();
        if let Err(e) = &collected {
            tracing::warn!("collect failed: {e:#}");
        }
        self.latest.publish(collected);
        self.fresh.notify();
        Instant::now() + self.schedule.period()
    }
}

/// Loads the BPF programs on a collector thread and returns once its first report is in.
pub fn start() -> anyhow::Result<(Monitor, Feed)> {
    let open_object = Box::leak(Box::new(MaybeUninit::<OpenObject>::uninit()));
    let agent = BpfAgent::init(open_object)?;
    let (waker, wakes) = monitor::channel();
    let feed = Feed {
        latest: Latest::default(),
        fresh: Arc::new(Notify::new()),
        schedule: Schedule {
            intervals: Arc::default(),
            waker,
        },
    };
    let monitor = Monitor::start(
        "collector",
        SPACING,
        wakes,
        BpfCollector {
            agent,
            latest: feed.latest.clone(),
            fresh: feed.fresh.clone(),
            schedule: feed.schedule.clone(),
        },
    )?;
    Ok((monitor, feed))
}

#[cfg(test)]
impl Feed {
    pub fn without_collector() -> Self {
        let (waker, _) = monitor::channel();
        Self {
            latest: Latest::default(),
            fresh: Arc::new(Notify::new()),
            schedule: Schedule {
                intervals: Arc::default(),
                waker,
            },
        }
    }

    pub fn period(&self) -> Duration {
        self.schedule.period()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed() -> Feed {
        Feed::without_collector()
    }

    #[test]
    fn nobody_watching_ticks_at_the_idle_period() {
        assert_eq!(feed().schedule.period(), IDLE_PERIOD);
    }

    #[test]
    fn the_shortest_live_watch_sets_the_period() {
        let feed = feed();
        let slow = feed.lease(Duration::from_secs(5));
        let fast = feed.lease(Duration::from_millis(200));
        assert_eq!(feed.schedule.period(), Duration::from_millis(200));
        drop(fast);
        assert_eq!(feed.schedule.period(), Duration::from_secs(5));
        drop(slow);
        assert_eq!(feed.schedule.period(), IDLE_PERIOD);
    }

    #[test]
    fn two_watches_at_one_interval_are_two_leases() {
        let feed = feed();
        let a = feed.lease(Duration::from_millis(300));
        let _b = feed.lease(Duration::from_millis(300));
        drop(a);
        assert_eq!(feed.schedule.period(), Duration::from_millis(300));
    }
}
