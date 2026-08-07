use crate::name_cache::NameCache;
use rustc_hash::{FxHashMap, FxHashSet};
use std::time::Instant;
use crate::report::{MachineStats, ProcessStats};

struct ProcHistory {
    cpu_runtime_ns: u64,
    time: Instant,
}

pub struct ProcessMetricsState {
    history: FxHashMap<u32, ProcHistory>,
    current_pids: FxHashSet<u32>,
    raw_buf: Vec<RawProcessStats>,
    num_cpus: usize,
}

impl ProcessMetricsState {
    pub fn new(num_cpus: usize) -> Self {
        Self {
            history: FxHashMap::default(),
            current_pids: FxHashSet::default(),
            raw_buf: Vec::with_capacity(512),
            num_cpus,
        }
    }

    pub fn normalize(
        &mut self,
        raw_data: impl Iterator<Item = RawProcessStats>,
        names: &NameCache,
    ) -> Vec<ProcessStats> {
        let now = Instant::now();

        self.raw_buf.clear();
        self.raw_buf.extend(raw_data);

        self.current_pids.clear();
        self.current_pids
            .extend(self.raw_buf.iter().map(|r| r.global_pid));
        self.history
            .retain(|pid, _| self.current_pids.contains(pid));

        self.raw_buf
            .iter()
            .map(|raw| {
                let prev = self.history.insert(
                    raw.global_pid,
                    ProcHistory {
                        cpu_runtime_ns: raw.cpu_runtime_ns,
                        time: now,
                    },
                );
                let cpu_percent = match prev {
                    Some(prev) => {
                        let elapsed_ns = now.duration_since(prev.time).as_nanos() as f64;
                        if elapsed_ns > 0.0 {
                            let delta_runtime =
                                raw.cpu_runtime_ns.saturating_sub(prev.cpu_runtime_ns) as f64;
                            let num_cpus = self.num_cpus.max(1) as f64;
                            ((delta_runtime / elapsed_ns) * 100.0 / num_cpus).clamp(0.0, 100.0)
                                as f32
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };

                ProcessStats {
                    global_pid: raw.global_pid,
                    local_pid: raw.local_pid,
                    mnt_ns: raw.mnt_ns,
                    pid_ns: raw.pid_ns,
                    name: names
                        .get(raw.global_pid)
                        .cloned()
                        .unwrap_or(UNKNOWN_PROCESS_NAME),

                    cpu_percent,
                    rss_kb: raw.rss_kb,
                    last_active_ns: raw.last_active_ns,

                    vsock_rx_bytes: raw.vsock_rx_bytes,
                    vsock_tx_bytes: raw.vsock_tx_bytes,

                    p9_rx_bytes: raw.p9_rx_bytes,
                    p9_tx_bytes: raw.p9_tx_bytes,

                    tcp_tx_lo_bytes: raw.tcp_tx_lo_bytes,
                    tcp_rx_lo_bytes: raw.tcp_rx_lo_bytes,

                    tcp_tx_remote_bytes: raw.tcp_tx_remote_bytes,
                    tcp_rx_remote_bytes: raw.tcp_rx_remote_bytes,

                    udp_tx_lo_bytes: raw.udp_tx_lo_bytes,
                    udp_rx_lo_bytes: raw.udp_rx_lo_bytes,

                    udp_tx_remote_bytes: raw.udp_tx_remote_bytes,
                    udp_rx_remote_bytes: raw.udp_rx_remote_bytes,

                    uds_tx_bytes: raw.uds_tx_bytes,
                    uds_rx_bytes: raw.uds_rx_bytes,

                    disk_read_bytes: raw.disk_read_bytes,
                    disk_write_bytes: raw.disk_write_bytes,

                    disk_read_iops: raw.disk_read_iops,
                    disk_write_iops: raw.disk_write_iops,

                    pipe_read_bytes: raw.pipe_read_bytes,
                    pipe_write_bytes: raw.pipe_write_bytes,

                    sendfile_bytes: raw.sendfile_bytes,
                }
            })
            .collect()
    }
    pub fn read_machine_stats(&self, percpu_bytes: &[u8]) -> MachineStats {
        let stride = size_of::<RawMachineStats>();
        if percpu_bytes.len() < stride * self.num_cpus {
            return MachineStats::default();
        }

        let cpu0: &RawMachineStats = unsafe { &*(percpu_bytes.as_ptr() as *const RawMachineStats) };

        let mut acc = RawMachineStats::default();
        for cpu in 0..self.num_cpus {
            let s: &RawMachineStats =
                unsafe { &*(percpu_bytes.as_ptr().add(cpu * stride) as *const RawMachineStats) };
            acc.busy_ns += s.busy_ns;
            acc.vsock_rx_bytes += s.vsock_rx_bytes;
            acc.vsock_tx_bytes += s.vsock_tx_bytes;
            acc.p9_rx_bytes += s.p9_rx_bytes;
            acc.p9_tx_bytes += s.p9_tx_bytes;
            acc.tcp_tx_lo_bytes += s.tcp_tx_lo_bytes;
            acc.tcp_rx_lo_bytes += s.tcp_rx_lo_bytes;
            acc.tcp_tx_remote_bytes += s.tcp_tx_remote_bytes;
            acc.tcp_rx_remote_bytes += s.tcp_rx_remote_bytes;
            acc.udp_tx_lo_bytes += s.udp_tx_lo_bytes;
            acc.udp_rx_lo_bytes += s.udp_rx_lo_bytes;
            acc.udp_tx_remote_bytes += s.udp_tx_remote_bytes;
            acc.udp_rx_remote_bytes += s.udp_rx_remote_bytes;
            acc.uds_tx_bytes += s.uds_tx_bytes;
            acc.uds_rx_bytes += s.uds_rx_bytes;
            acc.disk_read_bytes += s.disk_read_bytes;
            acc.disk_write_bytes += s.disk_write_bytes;
            acc.disk_read_iops += s.disk_read_iops;
            acc.disk_write_iops += s.disk_write_iops;
            acc.pipe_read_bytes += s.pipe_read_bytes;
            acc.pipe_write_bytes += s.pipe_write_bytes;
            acc.sendfile_bytes += s.sendfile_bytes;
        }

        MachineStats {
            busy_ns: acc.busy_ns,
            vsock_rx_bytes: acc.vsock_rx_bytes,
            vsock_tx_bytes: acc.vsock_tx_bytes,
            p9_rx_bytes: acc.p9_rx_bytes,
            p9_tx_bytes: acc.p9_tx_bytes,
            tcp_tx_lo_bytes: acc.tcp_tx_lo_bytes,
            tcp_rx_lo_bytes: acc.tcp_rx_lo_bytes,
            tcp_tx_remote_bytes: acc.tcp_tx_remote_bytes,
            tcp_rx_remote_bytes: acc.tcp_rx_remote_bytes,
            udp_tx_lo_bytes: acc.udp_tx_lo_bytes,
            udp_rx_lo_bytes: acc.udp_rx_lo_bytes,
            udp_tx_remote_bytes: acc.udp_tx_remote_bytes,
            udp_rx_remote_bytes: acc.udp_rx_remote_bytes,
            uds_tx_bytes: acc.uds_tx_bytes,
            uds_rx_bytes: acc.uds_rx_bytes,
            disk_read_bytes: acc.disk_read_bytes,
            disk_write_bytes: acc.disk_write_bytes,
            disk_read_iops: acc.disk_read_iops,
            disk_write_iops: acc.disk_write_iops,
            pipe_read_bytes: acc.pipe_read_bytes,
            pipe_write_bytes: acc.pipe_write_bytes,
            sendfile_bytes: acc.sendfile_bytes,

            last_tsc: cpu0.last_tsc,
            total_kb: cpu0.total_kb,
            free_kb: cpu0.free_kb,
            cached_kb: cpu0.cached_kb,
            available_kb: cpu0.available_kb,
            used_kb: cpu0.used_kb,
        }
    }
}

pub const UNKNOWN_PROCESS_NAME: [u8; 64] = {
    let mut buf = [0u8; 64];
    let src = b"<unknown>";
    let mut i = 0;
    while i < src.len() {
        buf[i] = src[i];
        i += 1;
    }
    buf
};

// SAFETY: both Raw* structs are #[repr(C)], made only of primitive integer
// fields (no padding-sensitive niches, no pointers), and must stay
// byte-compatible with the aya-ebpf-side MachineStats/ProcessStats structs
// in uniproc-linux-agent-ebpf/src/maps.rs (field-for-field, same order).
unsafe impl aya::Pod for RawMachineStats {}
unsafe impl aya::Pod for RawProcessStats {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct RawMachineStats {
    pub busy_ns: u64,
    pub last_tsc: u64,

    pub total_kb: u64,
    pub free_kb: u64,
    pub cached_kb: u64,
    pub available_kb: u64,
    pub used_kb: u64,

    pub vsock_rx_bytes: u64,
    pub vsock_tx_bytes: u64,

    pub p9_rx_bytes: u64,
    pub p9_tx_bytes: u64,

    pub tcp_tx_lo_bytes: u64,
    pub tcp_rx_lo_bytes: u64,

    pub tcp_tx_remote_bytes: u64,
    pub tcp_rx_remote_bytes: u64,

    pub udp_tx_lo_bytes: u64,
    pub udp_rx_lo_bytes: u64,

    pub udp_tx_remote_bytes: u64,
    pub udp_rx_remote_bytes: u64,

    pub uds_tx_bytes: u64,
    pub uds_rx_bytes: u64,

    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,

    pub disk_read_iops: u64,
    pub disk_write_iops: u64,

    pub pipe_read_bytes: u64,
    pub pipe_write_bytes: u64,

    pub sendfile_bytes: u64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct RawProcessStats {
    pub global_pid: u32,
    pub local_pid: u32,
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub cpu_runtime_ns: u64,

    pub rss_kb: u64,

    pub last_active_ns: u64,

    pub vsock_rx_bytes: u64,
    pub vsock_tx_bytes: u64,

    pub p9_rx_bytes: u64,
    pub p9_tx_bytes: u64,

    pub tcp_tx_lo_bytes: u64,
    pub tcp_rx_lo_bytes: u64,

    pub tcp_tx_remote_bytes: u64,
    pub tcp_rx_remote_bytes: u64,

    pub udp_tx_lo_bytes: u64,
    pub udp_rx_lo_bytes: u64,

    pub udp_tx_remote_bytes: u64,
    pub udp_rx_remote_bytes: u64,

    pub uds_tx_bytes: u64,
    pub uds_rx_bytes: u64,

    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,

    pub disk_read_iops: u64,
    pub disk_write_iops: u64,

    pub pipe_read_bytes: u64,
    pub pipe_write_bytes: u64,

    pub sendfile_bytes: u64,
}
