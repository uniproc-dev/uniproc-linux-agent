#pragma once

#include "vmlinux.h"
#include "maps.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ============================================================
// utils
// ============================================================

#define ERR_CODE -1337

static __always_inline __u32 get_pid(void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

// ============================================================
// traffic direction + per-protocol update helpers
// ============================================================

typedef enum { TRAFFIC_TX, TRAFFIC_RX } traffic_dir_t;

#define GEN_UPDATE_FN(fn_name, tx_field, rx_field)                                  \
static __always_inline void fn_name(__u32 pid, __u64 len, traffic_dir_t dir) {      \
struct process_stats *ps = bpf_map_lookup_elem(&process_stats_map, &pid);       \
if (ps) {                                                                        \
if (dir == TRAFFIC_TX) __sync_fetch_and_add(&ps->tx_field, len);            \
else                   __sync_fetch_and_add(&ps->rx_field, len);            \
}                                                                                \
__u32 _zero = 0;                                                                 \
struct machine_stats *ms = bpf_map_lookup_elem(&machine_stats_map, &_zero);     \
if (ms) {                                                                        \
if (dir == TRAFFIC_TX) ms->tx_field += len;                                 \
else                   ms->rx_field += len;                                 \
}                                                                                \
}

GEN_UPDATE_FN(update_p9_stats,         p9_tx_bytes,         p9_rx_bytes)
GEN_UPDATE_FN(update_vsock_stats,      vsock_tx_bytes,      vsock_rx_bytes)
GEN_UPDATE_FN(update_tcp_remote_stats, tcp_tx_remote_bytes, tcp_rx_remote_bytes)
GEN_UPDATE_FN(update_tcp_lo_stats,     tcp_tx_lo_bytes,     tcp_rx_lo_bytes)
GEN_UPDATE_FN(update_uds_stats,        uds_tx_bytes,        uds_rx_bytes)
GEN_UPDATE_FN(update_udp_remote_stats, udp_tx_remote_bytes, udp_rx_remote_bytes)
GEN_UPDATE_FN(update_udp_lo_stats,     udp_tx_lo_bytes,     udp_rx_lo_bytes)
GEN_UPDATE_FN(update_disk_stats,       disk_write_bytes,    disk_read_bytes)
GEN_UPDATE_FN(update_pipe_stats,       pipe_write_bytes,    pipe_read_bytes)