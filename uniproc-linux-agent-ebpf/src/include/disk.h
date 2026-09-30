#pragma once

#include "vmlinux.h"
#include "maps.h"
#include "common.h"
#include <bpf/bpf_core_read.h>
#include "constants.h"

static __always_inline void increment_disk_iops(__u32 pid, traffic_dir_t dir) {
    struct process_stats *s = bpf_map_lookup_elem(&process_stats_map, &pid);
    if (!s) return;
    if (dir == TRAFFIC_TX) __sync_fetch_and_add(&s->disk_write_iops, 1);
    else                   __sync_fetch_and_add(&s->disk_read_iops,  1);
}

static __always_inline void add_sendfile_bytes(__u32 pid, __u64 len) {
    struct process_stats *ps = bpf_map_lookup_elem(&process_stats_map, &pid);
    if (ps) __sync_fetch_and_add(&ps->sendfile_bytes, len);
    __u32 zero = 0;
    struct machine_stats *ms = bpf_map_lookup_elem(&machine_stats_map, &zero);
    if (ms) ms->sendfile_bytes += len;
}
