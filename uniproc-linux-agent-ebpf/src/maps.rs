use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray},
};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MachineStats {
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
#[derive(Clone, Copy)]
pub struct ProcessStats {
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

#[map]
pub static PROCESS_STATS_MAP: HashMap<u32, ProcessStats> = HashMap::with_max_entries(4096, 0);

#[map]
pub static MACHINE_STATS_MAP: PerCpuArray<MachineStats> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static LAST_MEM_UPDATE_MAP: Array<u64> = Array::with_max_entries(1, 0);

#[map]
pub static SHIFT_MAP: Array<u32> = Array::with_max_entries(1, 0);

#[map]
pub static KSYM_ADDRS_MAP: Array<u64> = Array::with_max_entries(4, 0);
