// Socket traffic probes.
//
// Hooks:
//   fexit/sock_sendmsg  — accounts TX bytes for all socket families
//   fexit/sock_recvmsg  — accounts RX bytes for all socket families
//   kretprobe/p9_client_rpc — accounts 9P virtio traffic (WSL2 /mnt)

use crate::common::{
    get_pid, update_tcp_lo_stats, update_tcp_remote_stats, update_udp_lo_stats,
    update_udp_remote_stats, update_uds_stats, update_vsock_stats, update_p9_stats, TrafficDir,
};
use crate::constants::{AF_INET, AF_INET6, AF_UNIX, AF_VSOCK, IPPROTO_TCP, IPPROTO_UDP, SOCK_DGRAM, SOCK_STREAM};
use crate::loopback::{is_loopback_v4, is_loopback_v6};
use crate::vmlinux::{p9_req_t, socket};
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::{fexit, kretprobe};
use aya_ebpf::programs::{FExitContext, RetProbeContext};

#[inline(always)]
unsafe fn handle_socket_stats(sock_ptr: *const socket, size: u64, dir: TrafficDir, pid: u32) {
    if sock_ptr.is_null() {
        return;
    }
    let sk: *mut crate::vmlinux::sock =
        match bpf_probe_read_kernel(&(*sock_ptr).sk as *const *mut crate::vmlinux::sock) {
            Ok(sk) => sk,
            Err(_) => return,
        };
    if sk.is_null() {
        return;
    }
    let family: u16 = bpf_probe_read_kernel(&(*sk).__sk_common.skc_family as *const _).unwrap_or(0);
    let sock_type: i16 = bpf_probe_read_kernel(&(*sock_ptr).type_ as *const _).unwrap_or(0);
    let sock_type = sock_type as u16;

    match family {
        f if f == AF_UNIX => update_uds_stats(pid, size, dir),
        f if f == AF_VSOCK => update_vsock_stats(pid, size, dir),
        f if f == AF_INET || f == AF_INET6 => {
            let protocol: u16 = bpf_probe_read_kernel(&(*sk).sk_protocol as *const _).unwrap_or(0);
            let is_lo = if family == AF_INET {
                let daddr: u32 = bpf_probe_read_kernel(
                    &(*sk).__sk_common.__bindgen_anon_1.skc_addrpair as *const _,
                )
                .map(|pair: u64| (pair & 0xFFFF_FFFF) as u32)
                .unwrap_or(0);
                // skc_addrpair packs {skc_daddr, skc_rcv_saddr}; skc_daddr is the
                // low dword on little-endian.
                is_loopback_v4(daddr)
            } else {
                is_loopback_v6(&(*sk).__sk_common.skc_v6_daddr as *const _)
            };

            if protocol == IPPROTO_TCP || sock_type == SOCK_STREAM {
                if is_lo {
                    update_tcp_lo_stats(pid, size, dir);
                } else {
                    update_tcp_remote_stats(pid, size, dir);
                }
            } else if protocol == IPPROTO_UDP || sock_type == SOCK_DGRAM {
                if is_lo {
                    update_udp_lo_stats(pid, size, dir);
                } else {
                    update_udp_remote_stats(pid, size, dir);
                }
            }
        }
        _ => {}
    }
}

#[fexit(function = "sock_sendmsg")]
pub fn socket_tracing_enter(ctx: FExitContext) -> i32 {
    unsafe {
        let ret: i64 = ctx.arg(2);
        if ret <= 0 {
            return 0;
        }
        let sock_ptr: *const socket = ctx.arg(0);
        handle_socket_stats(sock_ptr, ret as u64, TrafficDir::Tx, get_pid());
    }
    0
}

#[fexit(function = "sock_recvmsg")]
pub fn socket_tracing_exit(ctx: FExitContext) -> i32 {
    unsafe {
        let ret: i64 = ctx.arg(3);
        if ret <= 0 {
            return 0;
        }
        let sock_ptr: *const socket = ctx.arg(0);
        handle_socket_stats(sock_ptr, ret as u64, TrafficDir::Rx, get_pid());
    }
    0
}

#[kretprobe]
pub fn p9_client_rpc_kretprobe(ctx: RetProbeContext) -> u32 {
    unsafe {
        let req_ptr: *const p9_req_t = match ctx.ret() {
            Some(p) => p,
            None => return 0,
        };
        if req_ptr.is_null() || (req_ptr as i64) > -4096i64 {
            return 0;
        }
        let pid = get_pid();
        let tx_size: u32 = bpf_probe_read_kernel(&(*req_ptr).tc.size as *const _).unwrap_or(0);
        let rx_size: u32 = bpf_probe_read_kernel(&(*req_ptr).rc.size as *const _).unwrap_or(0);
        if tx_size > 0 {
            update_p9_stats(pid, tx_size as u64, TrafficDir::Tx);
        }
        if rx_size > 0 {
            update_p9_stats(pid, rx_size as u64, TrafficDir::Rx);
        }
    }
    0
}
