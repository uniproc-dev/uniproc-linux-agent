#pragma once

#include "vmlinux.h"
#include "constants.h"
#include "common.h"
#include "loopback.h"
#include <bpf/bpf_core_read.h>

static __always_inline int handle_socket_stats(struct sock *sk, __u64 size,
                                               traffic_dir_t dir, __u32 pid) {
    if (!sk) return ERR_CODE;

    __u16 family    = BPF_CORE_READ(sk, __sk_common.skc_family);
    __u16 sock_type = BPF_CORE_READ(sk, sk_type);

    switch (family) {
        case AF_UNIX:
            update_uds_stats(pid, size, dir);
            break;
        case AF_VSOCK:
            update_vsock_stats(pid, size, dir);
            break;
        case AF_INET:
        case AF_INET6: {
            __u16 protocol = BPF_CORE_READ(sk, sk_protocol);
            bool is_lo;
            if (family == AF_INET) {
                __u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
                is_lo = is_loopback_v4(daddr);
            } else {
                struct in6_addr daddr6 = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
                is_lo = is_loopback_v6(&daddr6);
            }
            if (protocol == IPPROTO_TCP || sock_type == SOCK_STREAM) {
                if (is_lo) update_tcp_lo_stats(pid, size, dir);
                else       update_tcp_remote_stats(pid, size, dir);
            } else if (protocol == IPPROTO_UDP || sock_type == SOCK_DGRAM) {
                if (is_lo) update_udp_lo_stats(pid, size, dir);
                else       update_udp_remote_stats(pid, size, dir);
            }
            break;
        }
        default:
            return ERR_CODE;
    }
    return 0;
}