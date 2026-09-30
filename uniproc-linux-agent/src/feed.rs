use std::mem::MaybeUninit;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use libbpf_rs::OpenObject;
use uniproc_agent_kit::monitor::{self, Collector, Monitor, Waker, Why};
use uniproc_agent_kit::{Latest, Notify};

use crate::bpf::BpfAgent;
use crate::model::Snapshot;
use crate::snapshots::Snapshots;

const IDLE_PERIOD: Duration = Duration::from_secs(1);
const SPACING: Duration = Duration::from_millis(50);

/// The collector's latest snapshot, a signal for each new one, and the
/// intervals watchers want it at.
#[derive(Clone)]
pub struct Feed {
    pub latest: Latest<Snapshot>,
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

    /// Asks the collector for a snapshot now, within its spacing.
    pub fn wake(&self) {
        self.schedule.waker.wake();
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
    snapshots: Snapshots,
    latest: Latest<Snapshot>,
    fresh: Arc<Notify>,
    schedule: Schedule,
}

impl Collector for BpfCollector {
    fn tick(&mut self, _: Why) -> Instant {
        match self.snapshots.take() {
            Ok(snapshot) => self.latest.replace(snapshot),
            Err(e) => {
                tracing::warn!("collect failed: {e:#}");
                self.latest.fail(format!("{e:#}"));
            }
        }
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
        latest: Latest::new(Snapshot::empty()),
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
            snapshots: Snapshots::new(agent),
            latest: feed.latest.clone(),
            fresh: feed.fresh.clone(),
            schedule: feed.schedule.clone(),
        },
    )?;
    if let Err(e) = feed.latest.get() {
        anyhow::bail!("the first snapshot failed: {e}");
    }
    Ok((monitor, feed))
}

#[cfg(test)]
impl Feed {
    pub fn without_collector() -> Self {
        let (waker, _) = monitor::channel();
        Self {
            latest: Latest::new(Snapshot::empty()),
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

    #[test]
    #[ignore = "loads the BPF programs: needs root and a kernel with BTF"]
    fn the_live_kernel_shows_this_very_process() {
        const CONTAINER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        struct Scope(std::path::PathBuf, std::process::Child);
        impl Drop for Scope {
            fn drop(&mut self) {
                let _ = self.1.kill();
                let _ = self.1.wait();
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let dir = std::path::PathBuf::from(format!("/sys/fs/cgroup/docker-{CONTAINER}.scope"));
        std::fs::create_dir(&dir).unwrap();
        let scope = Scope(dir, std::process::Command::new("sleep").arg("30").spawn().unwrap());
        std::fs::write(scope.0.join("cgroup.procs"), scope.1.id().to_string()).unwrap();

        let (_monitor, feed) = start().unwrap();
        let busy = Instant::now();
        while busy.elapsed() < Duration::from_millis(300) {
            std::hint::black_box(0u64.wrapping_add(1));
        }
        let first = feed.latest.get().unwrap().value;
        feed.schedule.waker.wake();
        let deadline = Instant::now() + Duration::from_secs(5);
        let snapshot = loop {
            let current = feed.latest.get().unwrap().value;
            if current.number > first.number {
                break current;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(20));
        };

        let pid = std::process::id();
        let (key, passport) = snapshot
            .passports
            .value
            .iter()
            .find(|(_, p)| p.view_pid == pid)
            .expect("this process is in the passports");
        let row = snapshot.rows.iter().find(|r| r.key == *key).unwrap();
        let state = &snapshot.states.value[key];
        let contained = snapshot
            .passports
            .value
            .values()
            .find(|p| p.view_pid == scope.1.id())
            .expect("the scoped sleep is in the passports");
        assert_eq!(contained.container.as_deref(), Some(CONTAINER));
        assert_eq!(passport.container, None);
        eprintln!("{passport:#?}\n{row:#?}\n{state:?}");

        assert!(!passport.cmdline.is_empty());
        assert!(passport.exe_path.contains("uniproc_linux_agent"));
        assert_eq!(passport.local_pid, pid);
        assert_ne!(key.pid, 0);
        assert!(row.cpu_run_time >= 2_000_000, "{} x100ns", row.cpu_run_time);
        assert!(row.cpu_user_time + row.cpu_kernel_time > 0);
        assert!(row.resident_set > 1 << 20);
        assert!(row.threads >= 2);
        assert!(row.probed.is_some());
        assert_eq!(state.nice, 0);

        let machine = &snapshot.machine;
        eprintln!("{:?}\n{:?}\n{:?}", machine.cpu, machine.memory, machine.load);
        assert!(machine.cpu.unwrap().count >= 1);
        assert!(machine.memory.unwrap().total > 0);
        assert!(machine.transports.is_some());
        assert!(!snapshot.environments.value.environments.is_empty());
        eprintln!("{} processes, {} environments", snapshot.rows.len(), snapshot.environments.value.environments.len());

        let collector_ticks = || -> std::collections::HashMap<std::ffi::OsString, u64> {
            std::fs::read_dir("/proc/self/task")
                .unwrap()
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let comm = std::fs::read_to_string(e.path().join("comm")).ok()?;
                    let stat = std::fs::read_to_string(e.path().join("stat")).ok()?;
                    (comm.trim() == "collector").then_some((e.file_name(), stat))
                })
                .map(|(tid, stat)| {
                    let fields: Vec<u64> = stat[stat.rfind(')').unwrap() + 2..]
                        .split_whitespace()
                        .map(|f| f.parse().unwrap_or(0))
                        .collect();
                    (tid, fields[11] + fields[12])
                })
                .collect()
        };
        let before = collector_ticks();
        let first = feed.latest.get().unwrap().value.number;
        std::thread::sleep(Duration::from_secs(10));
        let ticks = feed.latest.get().unwrap().value.number - first;
        let spent: u64 = collector_ticks()
            .iter()
            .filter_map(|(tid, after)| Some(after - before.get(tid)?))
            .sum();
        eprintln!("collector threads: {spent} clock ticks over {ticks} snapshots in 10 s");
    }
}
