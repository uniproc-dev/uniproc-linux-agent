use std::mem::size_of;

use crate::model::{Probed, Transports};

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

impl RawProcessStats {
    pub fn probed(&self) -> Probed {
        Probed {
            file_read_ops: self.disk_read_iops,
            file_write_ops: self.disk_write_iops,
            file_read_bytes: self.disk_read_bytes,
            file_write_bytes: self.disk_write_bytes,
            pipe_read_bytes: self.pipe_read_bytes,
            pipe_write_bytes: self.pipe_write_bytes,
            sendfile_bytes: self.sendfile_bytes,
            transports: Transports {
                tcp_loopback_rx: self.tcp_rx_lo_bytes,
                tcp_loopback_tx: self.tcp_tx_lo_bytes,
                tcp_remote_rx: self.tcp_rx_remote_bytes,
                tcp_remote_tx: self.tcp_tx_remote_bytes,
                udp_loopback_rx: self.udp_rx_lo_bytes,
                udp_loopback_tx: self.udp_tx_lo_bytes,
                udp_remote_rx: self.udp_rx_remote_bytes,
                udp_remote_tx: self.udp_tx_remote_bytes,
                unix_rx: self.uds_rx_bytes,
                unix_tx: self.uds_tx_bytes,
                vsock_rx: self.vsock_rx_bytes,
                vsock_tx: self.vsock_tx_bytes,
                p9_rx: self.p9_rx_bytes,
                p9_tx: self.p9_tx_bytes,
            },
        }
    }
}

/// Sums the per-CPU slots of machine_stats_map into the machine's transports.
pub fn machine_transports(percpu: &[Vec<u8>]) -> Transports {
    let mut t = Transports::default();
    for bytes in percpu {
        if bytes.len() < size_of::<RawMachineStats>() {
            continue;
        }
        let s: RawMachineStats =
            unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawMachineStats) };
        t.tcp_loopback_rx += s.tcp_rx_lo_bytes;
        t.tcp_loopback_tx += s.tcp_tx_lo_bytes;
        t.tcp_remote_rx += s.tcp_rx_remote_bytes;
        t.tcp_remote_tx += s.tcp_tx_remote_bytes;
        t.udp_loopback_rx += s.udp_rx_lo_bytes;
        t.udp_loopback_tx += s.udp_tx_lo_bytes;
        t.udp_remote_rx += s.udp_rx_remote_bytes;
        t.udp_remote_tx += s.udp_tx_remote_bytes;
        t.unix_rx += s.uds_rx_bytes;
        t.unix_tx += s.uds_tx_bytes;
        t.vsock_rx += s.vsock_rx_bytes;
        t.vsock_tx += s.vsock_tx_bytes;
        t.p9_rx += s.p9_rx_bytes;
        t.p9_tx += s.p9_tx_bytes;
    }
    t
}
