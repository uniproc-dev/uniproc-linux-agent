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
    last_window: Option<Instant>,
}

impl ProcessMetricsState {
    pub fn new(num_cpus: usize) -> Self {
        Self {
            history: FxHashMap::default(),
            current_pids: FxHashSet::default(),
            raw_buf: Vec::with_capacity(512),
            num_cpus,
            last_window: None,
        }
    }

    pub fn normalize(
        &mut self,
        raw_data: impl Iterator<Item = RawProcessStats>,
        names: &NameCache,
    ) -> Vec<ProcessStats> {
        let now = Instant::now();
        let window_start = self.last_window.replace(now);

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
                let since = prev.or(window_start.map(|time| ProcHistory {
                    cpu_runtime_ns: 0,
                    time,
                }));
                let cpu_percent = match since {
                    Some(prev) => cpu_percent(
                        raw.cpu_runtime_ns.saturating_sub(prev.cpu_runtime_ns),
                        now.duration_since(prev.time).as_nanos() as u64,
                        self.num_cpus,
                    ),
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

    /// Aggregates one entry of a `BPF_MAP_TYPE_PERCPU_ARRAY`, as returned by
    /// `Map::lookup_percpu()`: one buffer per possible CPU.
    ///
    /// Counters (`busy_ns`, traffic, disk) are accumulated by the eBPF program on
    /// whichever CPU the probe fired, so they must be summed. The memory fields
    /// (`total_kb`/`free_kb`/`cached_kb`/`available_kb`/`used_kb`) describe the whole
    /// machine and are overwritten wholesale by `update_mem_stats()` in the slot of
    /// the CPU that happened to run the refresh — summing them would be nonsense, and
    /// CPU 0 may never have run it. We therefore take them from the freshest slot,
    /// i.e. the one with the largest `last_tsc`.
    pub fn read_machine_stats(&self, percpu: &[Vec<u8>]) -> MachineStats {
        let stride = size_of::<RawMachineStats>();

        if percpu.is_empty() {
            tracing::warn!("machine_stats_map returned no per-CPU values");
            return MachineStats::default();
        }
        if percpu.len() != self.num_cpus {
            tracing::warn!(
                "machine_stats_map returned {} per-CPU values, expected {}",
                percpu.len(),
                self.num_cpus
            );
        }

        let mut acc = RawMachineStats::default();
        let mut freshest = RawMachineStats::default();

        for bytes in percpu {
            if bytes.len() < stride {
                tracing::warn!(
                    "machine_stats per-CPU value is {} bytes, expected at least {}",
                    bytes.len(),
                    stride
                );
                continue;
            }
            // SAFETY: RawMachineStats is repr(C), all-u64, so any byte pattern of
            // sufficient length is a valid value; read unaligned since the buffer
            // alignment is not guaranteed.
            let s: RawMachineStats =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawMachineStats) };

            if s.last_tsc >= freshest.last_tsc {
                freshest = s;
            }

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
            cpu_count: self.num_cpus as u32,

            last_tsc: freshest.last_tsc,
            total_kb: freshest.total_kb,
            free_kb: freshest.free_kb,
            cached_kb: freshest.cached_kb,
            available_kb: freshest.available_kb,
            used_kb: freshest.used_kb,
        }
    }
}

fn cpu_percent(runtime_ns: u64, elapsed_ns: u64, num_cpus: usize) -> f32 {
    if elapsed_ns == 0 {
        return 0.0;
    }
    let num_cpus = num_cpus.max(1) as f64;
    ((runtime_ns as f64 / elapsed_ns as f64) * 100.0 / num_cpus).clamp(0.0, 100.0) as f32
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

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(global_pid: u32, cpu_runtime_ns: u64) -> RawProcessStats {
        RawProcessStats {
            global_pid,
            cpu_runtime_ns,
            ..Default::default()
        }
    }

    fn cpu_of(stats: &[ProcessStats], pid: u32) -> f32 {
        stats.iter().find(|p| p.global_pid == pid).unwrap().cpu_percent
    }

    #[test]
    fn the_agents_first_window_has_no_cpu_to_report() {
        let mut state = ProcessMetricsState::new(1);
        let names = NameCache::new(-1);
        let first = state.normalize([raw(1, 5_000_000_000)].into_iter(), &names);
        assert_eq!(cpu_of(&first, 1), 0.0);
    }

    #[test]
    fn a_process_first_seen_later_is_measured_over_the_last_window() {
        let mut state = ProcessMetricsState::new(1);
        let names = NameCache::new(-1);
        state.normalize([raw(1, 0)].into_iter(), &names);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = state.normalize([raw(1, 0), raw(2, 10_000_000)].into_iter(), &names);
        let cpu = cpu_of(&second, 2);
        assert!(cpu > 0.0 && cpu <= 50.0, "{cpu}");
        assert_eq!(cpu_of(&second, 1), 0.0);
    }

    #[test]
    fn cpu_is_spread_over_every_cpu_and_capped() {
        assert_eq!(cpu_percent(1_000, 1_000, 4), 25.0);
        assert_eq!(cpu_percent(10_000, 1_000, 1), 100.0);
        assert_eq!(cpu_percent(1, 0, 1), 0.0);
    }
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
