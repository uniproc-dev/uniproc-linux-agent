use crate::maps::{MachineStats, ProcessStats, MACHINE_STATS_MAP, PROCESS_STATS_MAP};

pub const ERR_CODE: i64 = -1337;

#[inline(always)]
pub fn get_pid() -> u32 {
    (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrafficDir {
    Tx,
    Rx,
}

/// Mirrors the GEN_UPDATE_FN macro in common.h: bumps both the per-process
/// and machine-wide counters for a given traffic kind.
macro_rules! gen_update_fn {
    ($name:ident, $tx_field:ident, $rx_field:ident) => {
        #[inline(always)]
        pub fn $name(pid: u32, len: u64, dir: TrafficDir) {
            if let Some(ps) = unsafe { PROCESS_STATS_MAP.get_ptr_mut(&pid) } {
                let ps: &mut ProcessStats = unsafe { &mut *ps };
                match dir {
                    TrafficDir::Tx => ps.$tx_field += len,
                    TrafficDir::Rx => ps.$rx_field += len,
                }
            }
            if let Some(ms) = MACHINE_STATS_MAP.get_ptr_mut(0) {
                let ms: &mut MachineStats = unsafe { &mut *ms };
                match dir {
                    TrafficDir::Tx => ms.$tx_field += len,
                    TrafficDir::Rx => ms.$rx_field += len,
                }
            }
        }
    };
}

gen_update_fn!(update_p9_stats, p9_tx_bytes, p9_rx_bytes);
gen_update_fn!(update_vsock_stats, vsock_tx_bytes, vsock_rx_bytes);
gen_update_fn!(update_tcp_remote_stats, tcp_tx_remote_bytes, tcp_rx_remote_bytes);
gen_update_fn!(update_tcp_lo_stats, tcp_tx_lo_bytes, tcp_rx_lo_bytes);
gen_update_fn!(update_uds_stats, uds_tx_bytes, uds_rx_bytes);
gen_update_fn!(update_udp_remote_stats, udp_tx_remote_bytes, udp_rx_remote_bytes);
gen_update_fn!(update_udp_lo_stats, udp_tx_lo_bytes, udp_rx_lo_bytes);
gen_update_fn!(update_disk_stats, disk_write_bytes, disk_read_bytes);
gen_update_fn!(update_pipe_stats, pipe_write_bytes, pipe_read_bytes);

#[inline(always)]
pub fn increment_disk_iops(pid: u32, dir: TrafficDir) {
    if let Some(ps) = unsafe { PROCESS_STATS_MAP.get_ptr_mut(&pid) } {
        let ps: &mut ProcessStats = unsafe { &mut *ps };
        match dir {
            TrafficDir::Tx => ps.disk_write_iops += 1,
            TrafficDir::Rx => ps.disk_read_iops += 1,
        }
    }
}
