use crate::batch_lookup::BatchLookup;
use crate::environment_resolver::EnvironmentResolver;
use crate::iter_gc::IterGc;
use crate::name_cache::NameCache;
use crate::process_metrics_state::{ProcessMetricsState, RawMachineStats, RawProcessStats};
use crate::seed;
use anyhow::{anyhow, Context};
use aya::maps::{Array, HashMap as AyaHashMap, Map, MapData, PerCpuArray};
use aya::programs::{FExit, Iter, KProbe, TracePoint};
use aya::{Btf, EbpfLoader};
use std::os::fd::{AsFd, AsRawFd, RawFd};
use uniproc_protocol::{LinuxDockerContainerInfo, LinuxEnvironmentInfo, MachineStats, ProcessStats};

pub struct BpfAgent {
    ebpf: aya::Ebpf,
    gc: IterGc,
    cache: NameCache,
    batch: BatchLookup,
    metrics: ProcessMetricsState,
    environments: EnvironmentResolver,
}

impl BpfAgent {
    pub fn init() -> anyhow::Result<Self> {
        setup_rlimits()?;

        let mut ebpf = EbpfLoader::new()
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/uniproc-linux-agent"
            )))
            .context("failed to load eBPF object")?;

        setup_mem_config(&mut ebpf)?;
        setup_kernel_symbols(&mut ebpf)?;
        attach_programs(&mut ebpf)?;

        let seed_fd = program_fd(&mut ebpf, "seed_processes")?;
        seed::seed_existing_processes(seed_fd)?;

        let iter_fd = program_fd(&mut ebpf, "list_processes")?;
        let names_fd = program_fd(&mut ebpf, "task_names")?;

        let num_cpus = aya::util::nr_cpus().unwrap_or(1);

        Ok(Self {
            gc: IterGc::new(10, iter_fd),
            cache: NameCache::new(names_fd),
            batch: BatchLookup::new(),
            metrics: ProcessMetricsState::new(num_cpus),
            environments: EnvironmentResolver::new(),
            ebpf,
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
        let process_map_data = map_data(&self.ebpf, "PROCESS_STATS_MAP")?;
        let map_fd = process_map_data.fd().as_fd().as_raw_fd();
        let max_entries = process_map_data.info()?.max_entries();

        let keys: Vec<u32> = {
            let typed: AyaHashMap<&MapData, u32, RawProcessStats> =
                AyaHashMap::try_from(self.ebpf.map("PROCESS_STATS_MAP").unwrap())?;
            typed.keys().filter_map(|k| k.ok()).collect()
        };

        let _ = self.gc.maybe_gc(map_fd, keys.into_iter());
        let _ = self.cache.refresh(self.gc.live_pids());

        let machine = match self.ebpf.map("MACHINE_STATS_MAP") {
            Some(map) => {
                let percpu: PerCpuArray<&MapData, RawMachineStats> = PerCpuArray::try_from(map)?;
                match percpu.get(&0, 0) {
                    Ok(values) => {
                        let stats: Vec<RawMachineStats> = values.iter().copied().collect();
                        let bytes: &[u8] = unsafe {
                            std::slice::from_raw_parts(
                                stats.as_ptr() as *const u8,
                                stats.len() * std::mem::size_of::<RawMachineStats>(),
                            )
                        };
                        self.metrics.read_machine_stats(bytes)
                    }
                    Err(_) => MachineStats::default(),
                }
            }
            None => MachineStats::default(),
        };

        let batch = self.batch.lookup(map_fd, max_entries)?;
        let processes = self.metrics.normalize(batch.iter().copied(), &self.cache);
        let (environments, docker_containers) = self.environments.resolve(&processes);
        Ok((processes, environments, docker_containers, machine))
    }

    pub fn name_cache(&self) -> &NameCache {
        &self.cache
    }
}

/// Digs the raw `&MapData` (and thus its fd) out of the untyped `Map` enum
/// aya hands back from `Ebpf::map()`. aya's HashMap batch-lookup/delete gap
/// (see batch_lookup.rs/iter_gc.rs) means we need this raw fd regardless of
/// which typed wrapper we also use for safe access.
fn map_data<'a>(ebpf: &'a aya::Ebpf, name: &str) -> anyhow::Result<&'a MapData> {
    match ebpf.map(name).ok_or_else(|| anyhow!("{name} not found"))? {
        Map::HashMap(d) | Map::Array(d) | Map::PerCpuArray(d) => Ok(d),
        _ => Err(anyhow!("{name} is not a HashMap/Array/PerCpuArray")),
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

fn setup_mem_config(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
    let shift = (page_size.trailing_zeros() - 10) as u32;

    let mut shift_map: Array<&mut MapData, u32> = Array::try_from(
        ebpf.map_mut("SHIFT_MAP")
            .ok_or_else(|| anyhow!("SHIFT_MAP not found"))?,
    )?;
    shift_map.set(0, shift, 0)?;

    let mut last_update_map: Array<&mut MapData, u64> = Array::try_from(
        ebpf.map_mut("LAST_MEM_UPDATE_MAP")
            .ok_or_else(|| anyhow!("LAST_MEM_UPDATE_MAP not found"))?,
    )?;
    last_update_map.set(0, 1u64, 0)?;

    Ok(())
}

const KSYM_NAMES: [&str; 4] = [
    "_totalram_pages",
    "vm_zone_stat",
    "vm_node_stat",
    "totalreserve_pages",
];

fn setup_kernel_symbols(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
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

    let mut ksym_map: Array<&mut MapData, u64> = Array::try_from(
        ebpf.map_mut("KSYM_ADDRS_MAP")
            .ok_or_else(|| anyhow!("KSYM_ADDRS_MAP not found"))?,
    )?;

    for (i, addr) in addrs.iter().enumerate() {
        let addr = addr.ok_or_else(|| anyhow!("Symbol {} not found", KSYM_NAMES[i]))?;
        ksym_map.set(i as u32, addr, 0)?;
    }
    Ok(())
}

fn attach_programs(ebpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    let btf = Btf::from_sys_fs().context("failed to load /sys/kernel/btf/vmlinux")?;

    // fexit hooks: our aya-ebpf function name IS the target kernel function
    // name for vfs_read/vfs_write (fn == SEC target); for sock_sendmsg/
    // sock_recvmsg the Rust fn name differs from the kernel target, so list
    // both explicitly.
    for (name, target) in [
        ("vfs_read_exit", "vfs_read"),
        ("vfs_write_exit", "vfs_write"),
        ("vfs_iter_read_exit", "vfs_iter_read"),
        ("vfs_iter_write_exit", "vfs_iter_write"),
        ("socket_tracing_enter", "sock_sendmsg"),
        ("socket_tracing_exit", "sock_recvmsg"),
    ] {
        let program: &mut FExit = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("program {name} not found"))?
            .try_into()?;
        program.load(target, &btf)?;
        program.attach()?;
    }

    // kretprobe
    {
        let program: &mut KProbe = ebpf
            .program_mut("p9_client_rpc_kretprobe")
            .ok_or_else(|| anyhow!("program p9_client_rpc_kretprobe not found"))?
            .try_into()?;
        program.load()?;
        program.attach("p9_client_rpc", 0)?;
    }

    // kprobe
    {
        let program: &mut KProbe = ebpf
            .program_mut("handle_new_task")
            .ok_or_else(|| anyhow!("program handle_new_task not found"))?
            .try_into()?;
        program.load()?;
        program.attach("wake_up_new_task", 0)?;
    }

    // tracepoints
    for (name, category, event) in [
        ("global_cpu_monitor", "sched", "sched_stat_runtime"),
        ("handle_exec", "sched", "sched_process_exec"),
        ("handle_exit", "sched", "sched_process_exit"),
    ] {
        let program: &mut TracePoint = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("program {name} not found"))?
            .try_into()?;
        program.load()?;
        program.attach(category, event)?;
    }

    // The three bpf_iter/task programs (seed_processes, list_processes,
    // task_names) are intentionally NOT *attached* here via aya's Iter
    // program's attach() (which would create a persistent, always-open
    // iterator link): this codebase drives them itself via raw
    // BPF_LINK_CREATE/BPF_ITER_CREATE syscalls each time it needs to walk
    // the task list (see seed.rs/iter_gc.rs/name_cache.rs), exactly like the
    // libbpf-rs version did - just load() them so their prog fds are valid.
    // Iter::load() *does* need real BTF resolution ("task" iter target +
    // kernel BTF) unlike the naive hope in earlier revisions of this port;
    // if the hand-rolled iter/task programs in seed.rs weren't accepted by
    // the kernel/verifier as legitimate iter targets, this is where it will
    // surface first.
    for name in ["seed_processes", "list_processes", "task_names"] {
        let program: &mut Iter = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("program {name} not found"))?
            .try_into()?;
        program.load("task", &btf)?;
    }

    Ok(())
}

fn program_fd(ebpf: &mut aya::Ebpf, name: &str) -> anyhow::Result<RawFd> {
    let program = ebpf
        .program(name)
        .ok_or_else(|| anyhow!("program {name} not found"))?;
    Ok(program.fd()?.as_fd().as_raw_fd())
}
