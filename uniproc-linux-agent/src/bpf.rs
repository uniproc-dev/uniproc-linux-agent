use crate::batch_lookup::BatchLookup;
use crate::environment_resolver::read_namespace_inode;
use crate::iter_gc::IterGc;
use crate::model::{Probed, Transports};
use crate::probes;
use crate::seed;
use crate::tasks::{Task, TaskReader};
use anyhow::anyhow;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};
use rustc_hash::FxHashMap;
use std::mem::MaybeUninit;
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
}

/// What the kernel side holds at one moment.
pub struct Sample {
    pub tasks: Vec<Task>,
    pub probed: FxHashMap<u32, Probed>,
    pub transports: Option<Transports>,
}

impl<'a> BpfAgent<'a> {
    pub fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> anyhow::Result<Self> {
        setup_rlimits()?;

        let mut open_skel = ProgSkelBuilder::default().open(open_object)?;
        let own_pid_ns = read_namespace_inode(std::process::id(), "pid")
            .ok_or_else(|| anyhow!("cannot read the agent's own pid namespace"))?;
        open_skel
            .maps
            .rodata_data
            .as_deref_mut()
            .ok_or_else(|| anyhow!("the BPF object has no rodata"))?
            .agent_pid_ns = own_pid_ns;
        let mut skel = open_skel.load()?;

        setup_mem_config(&mut skel)?;
        setup_kernel_symbols(&mut skel)?;
        skel.attach()?;

        let seed_fd = skel.progs.seed_processes.as_fd().as_raw_fd();
        seed::seed_existing_processes(seed_fd)?;

        let iter_fd = skel.progs.list_processes.as_fd().as_raw_fd();

        Ok(Self {
            gc: IterGc::new(10, iter_fd),
            batch: BatchLookup::new(),
            tasks: TaskReader::new(),
            skel,
        })
    }

    pub fn sample(&mut self) -> anyhow::Result<Sample> {
        let _ = self.gc.maybe_gc(&mut self.skel.maps.process_stats_map);

        let link = self
            .skel
            .links
            .task_snapshot
            .as_ref()
            .ok_or_else(|| anyhow!("task_snapshot is not attached"))?;
        let tasks = self.tasks.read(link)?;

        let probed = self
            .batch
            .lookup(&self.skel.maps.process_stats_map)?
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

fn setup_mem_config(skel: &mut prog::ProgSkel) -> anyhow::Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let shift = (page_size.trailing_zeros() - 10) as u32;

    skel.maps
        .shift_map
        .update(&0u32.to_ne_bytes(), &shift.to_ne_bytes(), MapFlags::ANY)?;
    skel.maps.last_mem_update_map.update(
        &0u32.to_ne_bytes(),
        &1u64.to_ne_bytes(),
        MapFlags::ANY,
    )?;
    Ok(())
}

const KSYM_NAMES: [&str; 4] = [
    "_totalram_pages",
    "vm_zone_stat",
    "vm_node_stat",
    "totalreserve_pages",
];

fn setup_kernel_symbols(skel: &mut prog::ProgSkel) -> anyhow::Result<()> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let mut addrs = [None; KSYM_NAMES.len()];
    let mut remaining = KSYM_NAMES.len();

    let file = File::open("/proc/kallsyms")?;
    for line in BufReader::new(file).lines() {
        if remaining == 0 {
            break;
        }
        let line = line?;
        let mut p = line.split_whitespace();
        let addr = u64::from_str_radix(p.next().unwrap_or("0"), 16).unwrap_or(0);
        let _ = p.next();
        let Some(name) = p.next() else { continue };

        if let Some(idx) = KSYM_NAMES.iter().position(|&n| n == name) {
            if addrs[idx].is_none() {
                addrs[idx] = Some(addr);
                remaining -= 1;
            }
        }
    }

    for (i, addr) in addrs.iter().enumerate() {
        let addr = addr.ok_or_else(|| anyhow!("Symbol {} not found", KSYM_NAMES[i]))?;
        skel.maps.ksym_addrs_map.update(
            &(i as u32).to_ne_bytes(),
            &addr.to_ne_bytes(),
            MapFlags::ANY,
        )?;
    }
    Ok(())
}
