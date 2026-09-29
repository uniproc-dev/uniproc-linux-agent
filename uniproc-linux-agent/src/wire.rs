use uniproc_protocol::linux_capnp::{
    self, EnvironmentKind, MachineMetric, ProcessMetric, machine_sample, process_columns,
};

use crate::model::{
    CpuTimes, Environments, Key, Machine, Passport, Row, SchedPolicy, Snapshot, State, TaskState,
    Transports,
};
use crate::report::LinuxEnvironmentKind;

/// Which columns and machine groups one watch asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Wanted {
    processes: u64,
    machine: u64,
}

impl Wanted {
    pub fn read(spec: linux_capnp::metric_spec::Reader) -> capnp::Result<Self> {
        let mut wanted = Self::default();
        for metric in spec.get_processes()?.iter().flatten() {
            wanted.processes |= 1 << metric as u16;
        }
        for group in spec.get_machine()?.iter().flatten() {
            wanted.machine |= 1 << group as u16;
        }
        Ok(wanted)
    }

    fn process(&self, metric: ProcessMetric) -> bool {
        self.processes & (1 << metric as u16) != 0
    }

    fn group(&self, group: MachineMetric) -> bool {
        self.machine & (1 << group as u16) != 0
    }
}

pub fn process_info(p: &Passport, mut out: linux_capnp::process_info::Builder) {
    out.set_pid(p.key.pid);
    out.set_parent_pid(p.parent_pid);
    out.set_sequence_number(p.key.sequence_number);
    out.set_start_time(p.start_time);
    out.set_name(p.name.as_str());
    out.set_exe_path(p.exe_path.as_str());
    let mut cmdline = out.reborrow().init_cmdline(p.cmdline.len() as u32);
    for (i, arg) in p.cmdline.iter().enumerate() {
        cmdline.set(i as u32, arg.as_str());
    }
    out.set_uid(p.uid);
    out.set_user(p.user.as_str());
    out.set_local_pid(p.local_pid);
    out.set_mnt_ns(p.mnt_ns);
    out.set_pid_ns(p.pid_ns);
    out.set_cgroup(p.cgroup.as_str());
}

pub fn process_state(s: &State, mut out: linux_capnp::process_state::Builder) {
    out.set_pid(s.key.pid);
    out.set_sequence_number(s.key.sequence_number);
    out.set_state(match s.state {
        TaskState::Unknown => linux_capnp::TaskState::Unknown,
        TaskState::Running => linux_capnp::TaskState::Running,
        TaskState::Sleeping => linux_capnp::TaskState::Sleeping,
        TaskState::DiskSleep => linux_capnp::TaskState::DiskSleep,
        TaskState::Stopped => linux_capnp::TaskState::Stopped,
        TaskState::TracingStop => linux_capnp::TaskState::TracingStop,
        TaskState::Zombie => linux_capnp::TaskState::Zombie,
        TaskState::Idle => linux_capnp::TaskState::Idle,
    });
    out.set_nice(s.nice);
    out.set_policy(match s.policy {
        SchedPolicy::Unknown => linux_capnp::SchedPolicy::Unknown,
        SchedPolicy::Other => linux_capnp::SchedPolicy::Other,
        SchedPolicy::Fifo => linux_capnp::SchedPolicy::Fifo,
        SchedPolicy::Rr => linux_capnp::SchedPolicy::Rr,
        SchedPolicy::Batch => linux_capnp::SchedPolicy::Batch,
        SchedPolicy::Idle => linux_capnp::SchedPolicy::Idle,
        SchedPolicy::Deadline => linux_capnp::SchedPolicy::Deadline,
    });
    out.set_rt_priority(s.rt_priority);
}

pub fn process_key(key: Key, mut out: linux_capnp::process_key::Builder) {
    out.set_pid(key.pid);
    out.set_sequence_number(key.sequence_number);
}

pub fn environments(
    e: &Environments,
    mut environments: capnp::struct_list::Builder<linux_capnp::environment_info::Owned>,
) {
    for (i, env) in e.environments.iter().enumerate() {
        let mut dst = environments.reborrow().get(i as u32);
        dst.set_mnt_ns(env.mnt_ns);
        dst.set_pid_ns(env.pid_ns);
        match &env.kind {
            LinuxEnvironmentKind::Unknown => dst.set_kind(EnvironmentKind::Unknown),
            LinuxEnvironmentKind::CurrentDistro { name } => {
                dst.set_kind(EnvironmentKind::CurrentDistro);
                dst.set_name(name.as_str());
            }
            LinuxEnvironmentKind::DockerContainer { id } => {
                dst.set_kind(EnvironmentKind::DockerContainer);
                dst.set_name(id.as_str());
            }
            LinuxEnvironmentKind::UnknownExternalNamespace => {
                dst.set_kind(EnvironmentKind::UnknownExternalNamespace)
            }
        }
    }
}

pub fn docker_containers(
    e: &Environments,
    mut containers: capnp::struct_list::Builder<linux_capnp::docker_container_info::Owned>,
) {
    for (i, c) in e.docker_containers.iter().enumerate() {
        let mut dst = containers.reborrow().get(i as u32);
        dst.set_id(c.id.as_str());
        dst.set_mnt_ns(c.mnt_ns);
        dst.set_pid_ns(c.pid_ns);
        dst.set_api_version(c.api_version.as_str());
        dst.set_raw_json(c.raw_json.as_str());
    }
}

fn row_fn<T>(value: impl Fn(&Row) -> T) -> impl Fn(&Row) -> T {
    value
}

macro_rules! fill {
    ($list:expr, $rows:expr, $value:expr) => {{
        let mut list = $list;
        let value = row_fn($value);
        for (i, row) in $rows.iter().enumerate() {
            list.set(i as u32, value(row));
        }
    }};
}

macro_rules! column {
    ($wanted:expr, $out:expr, $rows:expr, $metric:ident, $init:ident, $value:expr) => {
        if $wanted.process(ProcessMetric::$metric) {
            fill!($out.reborrow().$init($rows.len() as u32), $rows, $value);
        }
    };
}

pub fn columns(snapshot: &Snapshot, wanted: Wanted, mut out: process_columns::Builder) {
    let rows = snapshot.rows.as_slice();
    let n = rows.len() as u32;
    out.set_snapshot(snapshot.number);
    out.set_sampled_at(snapshot.sampled_at);
    out.set_passport_etag(snapshot.passports.etag);
    fill!(out.reborrow().init_pids(n), rows, |r: &Row| r.key.pid);
    fill!(out.reborrow().init_sequence_numbers(n), rows, |r: &Row| r.key.sequence_number);

    column!(wanted, out, rows, CpuUserTime, init_cpu_user_time, |r| r.cpu_user_time);
    column!(wanted, out, rows, CpuKernelTime, init_cpu_kernel_time, |r| r.cpu_kernel_time);
    column!(wanted, out, rows, CpuRunTime, init_cpu_run_time, |r| r.cpu_run_time);
    column!(wanted, out, rows, ResidentSet, init_resident_set, |r| r.resident_set);
    column!(wanted, out, rows, ResidentAnon, init_resident_anon, |r| r.resident_anon);
    column!(wanted, out, rows, ResidentFile, init_resident_file, |r| r.resident_file);
    column!(wanted, out, rows, ResidentShmem, init_resident_shmem, |r| r.resident_shmem);
    column!(wanted, out, rows, PeakResidentSet, init_peak_resident_set, |r| r.peak_resident_set);
    column!(wanted, out, rows, VirtualSize, init_virtual_size, |r| r.virtual_size);
    column!(wanted, out, rows, PeakVirtualSize, init_peak_virtual_size, |r| r.peak_virtual_size);
    column!(wanted, out, rows, Swap, init_swap, |r| r.swap);
    column!(wanted, out, rows, MinorFaults, init_minor_faults, |r| r.minor_faults);
    column!(wanted, out, rows, MajorFaults, init_major_faults, |r| r.major_faults);
    column!(wanted, out, rows, Threads, init_threads, |r| r.threads);
    column!(wanted, out, rows, VoluntaryContextSwitches, init_voluntary_context_switches, |r| {
        r.voluntary_context_switches
    });
    column!(wanted, out, rows, InvoluntaryContextSwitches, init_involuntary_context_switches, |r| {
        r.involuntary_context_switches
    });
    column!(wanted, out, rows, IoReadOps, init_io_read_ops, |r| r.io_read_ops);
    column!(wanted, out, rows, IoWriteOps, init_io_write_ops, |r| r.io_write_ops);
    column!(wanted, out, rows, IoReadBytes, init_io_read_bytes, |r| r.io_read_bytes);
    column!(wanted, out, rows, IoWriteBytes, init_io_write_bytes, |r| r.io_write_bytes);
    column!(wanted, out, rows, DiskReadBytes, init_disk_read_bytes, |r| r.disk_read_bytes);
    column!(wanted, out, rows, DiskWriteBytes, init_disk_write_bytes, |r| r.disk_write_bytes);

    let probed = |value: fn(&crate::model::Probed) -> u64| move |r: &Row| r.probed.as_ref().map_or(u64::MAX, value);
    column!(wanted, out, rows, FileReadOps, init_file_read_ops, probed(|p| p.file_read_ops));
    column!(wanted, out, rows, FileWriteOps, init_file_write_ops, probed(|p| p.file_write_ops));
    column!(wanted, out, rows, FileReadBytes, init_file_read_bytes, probed(|p| p.file_read_bytes));
    column!(wanted, out, rows, FileWriteBytes, init_file_write_bytes, probed(|p| p.file_write_bytes));
    column!(wanted, out, rows, PipeReadBytes, init_pipe_read_bytes, probed(|p| p.pipe_read_bytes));
    column!(wanted, out, rows, PipeWriteBytes, init_pipe_write_bytes, probed(|p| p.pipe_write_bytes));
    column!(wanted, out, rows, SendfileBytes, init_sendfile_bytes, probed(|p| p.sendfile_bytes));
    column!(wanted, out, rows, NetRxBytes, init_net_rx_bytes, probed(|p| p.transports.net_rx()));
    column!(wanted, out, rows, NetTxBytes, init_net_tx_bytes, probed(|p| p.transports.net_tx()));

    if wanted.process(ProcessMetric::Transports) {
        let mut list = out.reborrow().init_transports(n);
        for (i, row) in rows.iter().enumerate() {
            let t = row.probed.map(|p| p.transports);
            transports(t.as_ref(), list.reborrow().get(i as u32));
        }
    }
}

fn transports(t: Option<&Transports>, mut out: linux_capnp::transports::Builder) {
    let none = Transports {
        tcp_loopback_rx: u64::MAX,
        tcp_loopback_tx: u64::MAX,
        tcp_remote_rx: u64::MAX,
        tcp_remote_tx: u64::MAX,
        udp_loopback_rx: u64::MAX,
        udp_loopback_tx: u64::MAX,
        udp_remote_rx: u64::MAX,
        udp_remote_tx: u64::MAX,
        unix_rx: u64::MAX,
        unix_tx: u64::MAX,
        vsock_rx: u64::MAX,
        vsock_tx: u64::MAX,
        p9_rx: u64::MAX,
        p9_tx: u64::MAX,
    };
    let t = t.unwrap_or(&none);
    out.set_tcp_loopback_rx(t.tcp_loopback_rx);
    out.set_tcp_loopback_tx(t.tcp_loopback_tx);
    out.set_tcp_remote_rx(t.tcp_remote_rx);
    out.set_tcp_remote_tx(t.tcp_remote_tx);
    out.set_udp_loopback_rx(t.udp_loopback_rx);
    out.set_udp_loopback_tx(t.udp_loopback_tx);
    out.set_udp_remote_rx(t.udp_remote_rx);
    out.set_udp_remote_tx(t.udp_remote_tx);
    out.set_unix_rx(t.unix_rx);
    out.set_unix_tx(t.unix_tx);
    out.set_vsock_rx(t.vsock_rx);
    out.set_vsock_tx(t.vsock_tx);
    out.set_p9_rx(t.p9_rx);
    out.set_p9_tx(t.p9_tx);
}

pub fn machine(snapshot: &Snapshot, wanted: Wanted, mut out: machine_sample::Builder) {
    let m: &Machine = &snapshot.machine;
    out.set_snapshot(snapshot.number);
    out.set_sampled_at(snapshot.sampled_at);

    if wanted.group(MachineMetric::Cpu)
        && let Some(cpu) = &m.cpu
    {
        let mut dst = out.reborrow().init_cpu();
        let t = &cpu.times;
        dst.set_user_time(t.user);
        dst.set_nice_time(t.nice);
        dst.set_system_time(t.system);
        dst.set_idle_time(t.idle);
        dst.set_iowait_time(t.iowait);
        dst.set_irq_time(t.irq);
        dst.set_softirq_time(t.softirq);
        dst.set_steal_time(t.steal);
        dst.set_guest_time(t.guest);
        dst.set_guest_nice_time(t.guest_nice);
        dst.set_count(cpu.count);
        dst.set_current_mhz(cpu.current_mhz);
    }

    if wanted.group(MachineMetric::Processors) {
        let mut list = out.reborrow().init_processors(m.processors.len() as u32);
        for (i, t) in m.processors.iter().enumerate() {
            processor(t, list.reborrow().get(i as u32));
        }
    }

    if wanted.group(MachineMetric::Memory)
        && let Some(mem) = &m.memory
    {
        let mut dst = out.reborrow().init_memory();
        dst.set_total(mem.total);
        dst.set_free(mem.free);
        dst.set_available(mem.available);
        dst.set_buffers(mem.buffers);
        dst.set_cached(mem.cached);
        dst.set_shmem(mem.shmem);
        dst.set_swap_total(mem.swap_total);
        dst.set_swap_free(mem.swap_free);
        dst.set_commit_limit(mem.commit_limit);
        dst.set_committed(mem.committed);
    }

    if wanted.group(MachineMetric::Disk)
        && let Some(disk) = &m.disk
    {
        let mut dst = out.reborrow().init_disk();
        dst.set_read_ops(disk.read_ops);
        dst.set_write_ops(disk.write_ops);
        dst.set_read_bytes(disk.read_bytes);
        dst.set_write_bytes(disk.write_bytes);
        dst.set_busy_time(disk.busy_time);
    }

    if wanted.group(MachineMetric::Network)
        && let Some(t) = &m.transports
    {
        let mut dst = out.reborrow().init_network();
        dst.set_rx_bytes(t.net_rx());
        dst.set_tx_bytes(t.net_tx());
        transports(Some(t), dst.init_transports());
    }

    if wanted.group(MachineMetric::NetworkAdapters) {
        let mut list = out.reborrow().init_network_adapters(m.adapters.len() as u32);
        for (i, a) in m.adapters.iter().enumerate() {
            let mut dst = list.reborrow().get(i as u32);
            dst.set_name(a.name.as_str());
            dst.set_hardware(a.hardware);
            dst.set_link_speed(a.link_speed);
            dst.set_up(a.up);
            dst.set_rx_bytes(a.rx_bytes);
            dst.set_tx_bytes(a.tx_bytes);
            dst.set_rx_packets(a.rx_packets);
            dst.set_tx_packets(a.tx_packets);
        }
    }

    if wanted.group(MachineMetric::Load)
        && let Some(load) = &m.load
    {
        let mut dst = out.reborrow().init_load();
        dst.set_load1(load.load1);
        dst.set_load5(load.load5);
        dst.set_load15(load.load15);
        dst.set_running(load.running);
        dst.set_tasks(load.tasks);
    }
}

fn processor(t: &CpuTimes, mut out: linux_capnp::machine_processor::Builder) {
    out.set_user_time(t.user);
    out.set_nice_time(t.nice);
    out.set_system_time(t.system);
    out.set_idle_time(t.idle);
    out.set_iowait_time(t.iowait);
    out.set_irq_time(t.irq);
    out.set_softirq_time(t.softirq);
    out.set_steal_time(t.steal);
}
