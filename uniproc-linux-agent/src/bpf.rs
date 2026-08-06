use crate::batch_lookup::BatchLookup;
use crate::environment_resolver::EnvironmentResolver;
use crate::iter_gc::IterGc;
use crate::name_cache::NameCache;
use crate::process_metrics_state::ProcessMetricsState;
use crate::seed;
use anyhow::anyhow;
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, OpenObject};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use uniproc_protocol::{LinuxDockerContainerInfo, LinuxEnvironmentInfo, MachineStats, ProcessStats};

mod prog {
    include!(concat!(env!("OUT_DIR"), "/prog.skel.rs"));
}
use prog::{ProgSkel, ProgSkelBuilder};

pub struct BpfAgent<'a> {
    skel: ProgSkel<'a>,
    gc: IterGc,
    cache: NameCache,
    batch: BatchLookup,
    metrics: ProcessMetricsState,
    environments: EnvironmentResolver,
}

impl<'a> BpfAgent<'a> {
    pub fn init(open_object: &'a mut MaybeUninit<OpenObject>) -> anyhow::Result<Self> {
        setup_rlimits()?;

        let open_skel = ProgSkelBuilder::default().open(open_object)?;
        let mut skel = open_skel.load()?;

        setup_mem_config(&mut skel)?;
        setup_kernel_symbols(&mut skel)?;
        skel.attach()?;

        let seed_fd = skel.progs.seed_processes.as_fd().as_raw_fd();
        seed::seed_existing_processes(seed_fd)?;

        let iter_fd = skel.progs.list_processes.as_fd().as_raw_fd();
        let names_fd = skel.progs.task_names.as_fd().as_raw_fd();

        Ok(Self {
            gc: IterGc::new(10, iter_fd),
            cache: NameCache::new(names_fd),
            batch: BatchLookup::new(),
            metrics: ProcessMetricsState::new(libbpf_rs::num_possible_cpus()?),
            environments: EnvironmentResolver::new(),
            skel,
        })
    }

    pub fn collect(
        &mut self,
    ) -> anyhow::Result<(
        Vec<ProcessStats>,
        Vec<LinuxEnvironmentInfo>,
        Vec<LinuxDockerContainerInfo>,
        MachineStats,
    )> {
        let map = &mut self.skel.maps.process_stats_map;
        let _ = self.gc.maybe_gc(map);
        let _ = self.cache.refresh(self.gc.live_pids());

        let machine = match self
            .skel
            .maps
            .machine_stats_map
            .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)
        {
            Ok(Some(bytes)) => self.metrics.read_machine_stats(&bytes),
            _ => MachineStats::default(),
        };

        let batch = self.batch.lookup(&self.skel.maps.process_stats_map)?;
        let processes = self.metrics.normalize(batch.iter().copied(), &self.cache);
        let (environments, docker_containers) = self.environments.resolve(&processes);
        Ok((processes, environments, docker_containers, machine))
    }

    pub fn name_cache(&self) -> &NameCache {
        &self.cache
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
