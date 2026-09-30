use crate::batch_lookup::BatchLookup;
use crate::environment_resolver::read_namespace_inode;
use crate::iter_gc::IterGc;
use crate::model::{Probed, Transports};
use crate::probes::{self, RawMachineStats, RawProcessStats};
use crate::seed;
use crate::tasks::{Task, TaskReader};
use anyhow::{Context, anyhow};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};
use rustc_hash::FxHashMap;
use std::mem::{MaybeUninit, size_of};
use std::os::fd::{AsFd, AsRawFd};

mod prog {
    include!(concat!(env!("OUT_DIR"), "/prog.skel.rs"));
}
use prog::{ProgSkel, ProgSkelBuilder};

pub struct BpfAgent<'a> {
    skel: ProgSkel<'a>,
    gc: IterGc,
    batch: BatchLookup,
    tasks: TaskReader,
    unprobed: u64,
}

/// What the kernel side holds at one moment.
pub struct Sample {
    pub tasks: Vec<Task>,
    pub probed: FxHashMap<u32, Probed>,
    pub transports: Option<Transports>,
}

impl<'a> BpfAgent<'a> {
    pub fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> anyhow::Result<Self> {
        check_kernel()?;
        setup_rlimits()?;

        let mut open_skel = ProgSkelBuilder::default()
            .open(open_object)
            .context("opening the BPF object")?;
        let own_pid_ns = read_namespace_inode(std::process::id(), "pid")
            .ok_or_else(|| anyhow!("cannot read the agent's own pid namespace"))?;
        open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("the BPF object has no rodata"))?
            .agent_pid_ns = own_pid_ns;
        let mut skel = open_skel.load().context("loading the BPF programs")?;
        check_layout(&skel.maps.process_stats_map, size_of::<RawProcessStats>())?;
        check_layout(&skel.maps.machine_stats_map, size_of::<RawMachineStats>())?;
        skel.attach().context("attaching the BPF programs")?;

        let seed_fd = skel.progs.seed_processes.as_fd().as_raw_fd();
        seed::seed_existing_processes(seed_fd).context("seeding the running processes")?;

        let iter_fd = skel.progs.list_processes.as_fd().as_raw_fd();

        Ok(Self {
            gc: IterGc::new(10, iter_fd),
            batch: BatchLookup::new(),
            tasks: TaskReader::new(),
            unprobed: 0,
            skel,
        })
    }

    pub fn sample(&mut self) -> anyhow::Result<Sample> {
        let _ = self.gc.maybe_gc(&mut self.skel.maps.process_stats_map);

        if let Some(bss) = self.skel.maps.bss_data.as_deref() {
            let unprobed = unsafe { std::ptr::read_volatile(&bss.process_stats_full) };
            if unprobed > self.unprobed {
                tracing::warn!(
                    "process_stats_map is full: {unprobed} processes have gone without probes so far"
                );
                self.unprobed = unprobed;
            }
        }

        let link = self
            .skel
            .links
            .task_snapshot
            .as_ref()
            .ok_or_else(|| anyhow!("task_snapshot is not attached"))?;
        let tasks = self.tasks.read(link).context("reading the task snapshot")?;

        let probed = self
            .batch
            .lookup(&self.skel.maps.process_stats_map)
            .context("reading process_stats_map")?
            .iter()
            .map(|raw| (raw.global_pid, raw.probed()))
            .collect();

        let transports = match self
            .skel
            .maps
            .machine_stats_map
            .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)
        {
            Ok(Some(per_cpu)) => Some(probes::machine_transports(&per_cpu)),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("machine_stats_map lookup_percpu failed: {e}");
                None
            }
        };

        Ok(Sample {
            tasks,
            probed,
            transports,
        })
    }
}

fn check_layout(map: &impl MapCore, value_size: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        map.key_size() as usize == size_of::<u32>() && map.value_size() as usize == value_size,
        "{:?} holds {}-byte keys and {}-byte values, the agent reads {} and {}",
        map.name(),
        map.key_size(),
        map.value_size(),
        size_of::<u32>(),
        value_size
    );
    Ok(())
}

fn setup_rlimits() -> anyhow::Result<()> {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        eprintln!("warning: failed to remove memlock limit");
    }
    Ok(())
}

/// The oldest kernel with the mm_struct layout of the committed vmlinux.h
/// (6.2) and the sock_send_length/sock_recv_length tracepoints (6.3).
const MIN_KERNEL: (u32, u32) = (6, 3);

fn check_kernel() -> anyhow::Result<()> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")?;
    let version = kernel_version(&release)
        .ok_or_else(|| anyhow!("cannot read the kernel version from {release:?}"))?;
    if version < MIN_KERNEL {
        anyhow::bail!(
            "kernel {} is too old: the agent needs {}.{} or newer",
            release.trim(),
            MIN_KERNEL.0,
            MIN_KERNEL.1
        );
    }
    Ok(())
}

fn kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.trim().split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_releases_parse_to_major_and_minor() {
        assert_eq!(kernel_version("6.18.33.1-microsoft-standard-WSL2\n"), Some((6, 18)));
        assert_eq!(kernel_version("5.15.167.4-microsoft-standard-WSL2"), Some((5, 15)));
        assert_eq!(kernel_version("6.2"), Some((6, 2)));
        assert_eq!(kernel_version("weird"), None);
        assert!(kernel_version("5.15.1").unwrap() < MIN_KERNEL);
        assert!(kernel_version("6.10.0").unwrap() >= MIN_KERNEL);
        assert!(kernel_version(&std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap()).is_some());
    }
}
