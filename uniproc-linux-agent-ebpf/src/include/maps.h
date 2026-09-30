#pragma once
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

struct machine_stats {
    __u64 vsock_rx_bytes;
    __u64 vsock_tx_bytes;
    __u64 p9_rx_bytes;
    __u64 p9_tx_bytes;
    __u64 tcp_tx_lo_bytes;
    __u64 tcp_rx_lo_bytes;
    __u64 tcp_tx_remote_bytes;
    __u64 tcp_rx_remote_bytes;
    __u64 udp_tx_lo_bytes;
    __u64 udp_rx_lo_bytes;
    __u64 udp_tx_remote_bytes;
    __u64 udp_rx_remote_bytes;
    __u64 uds_tx_bytes;
    __u64 uds_rx_bytes;
    __u64 disk_read_bytes;
    __u64 disk_write_bytes;
    __u64 disk_read_iops;
    __u64 disk_write_iops;
    __u64 pipe_read_bytes;
    __u64 pipe_write_bytes;
    __u64 sendfile_bytes;
};


struct process_stats {
    __u32 global_pid;
    __u32 local_pid;
    __u64 mnt_ns;
    __u64 pid_ns;
    __u64 vsock_rx_bytes;
    __u64 vsock_tx_bytes;
    __u64 p9_rx_bytes;
    __u64 p9_tx_bytes;
    __u64 tcp_tx_lo_bytes;
    __u64 tcp_rx_lo_bytes;
    __u64 tcp_tx_remote_bytes;
    __u64 tcp_rx_remote_bytes;
    __u64 udp_tx_lo_bytes;
    __u64 udp_rx_lo_bytes;
    __u64 udp_tx_remote_bytes;
    __u64 udp_rx_remote_bytes;
    __u64 uds_tx_bytes;
    __u64 uds_rx_bytes;
    __u64 disk_read_bytes;
    __u64 disk_write_bytes;
    __u64 disk_read_iops;
    __u64 disk_write_iops;
    __u64 pipe_read_bytes;
    __u64 pipe_write_bytes;
    __u64 sendfile_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, __u32);
    __type(value, struct process_stats);
} process_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct machine_stats);
} machine_stats_map SEC(".maps");
