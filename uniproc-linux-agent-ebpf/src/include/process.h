#pragma once

#include "vmlinux.h"
#include "maps.h"
#include "common.h"
#include "constants.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

__u64 process_stats_full = 0;

static __always_inline void insert_process_stats(__u32 tgid, struct process_stats *stats,
                                                 __u64 flags) {
    long err = bpf_map_update_elem(&process_stats_map, &tgid, stats, flags);
    if (err && err != -EEXIST)
        __sync_fetch_and_add(&process_stats_full, 1);
}

static __always_inline int get_local_tgid(struct task_struct *task, __u32 *out) {
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct pid         *pid_ptr = BPF_CORE_READ(leader, thread_pid);
    int                 level   = BPF_CORE_READ(pid_ptr, level);

    struct upid target = {};
    bpf_probe_read_kernel(&target, sizeof(target), &pid_ptr->numbers[level]);
    __u32 nr = target.nr;

    if (nr == 0)
        nr = (__u32)BPF_CORE_READ(leader, tgid);

    *out = nr;
    return nr == 0 ? ERR_CODE : 0;
}

static __always_inline int get_mnt_ns_id(struct task_struct *task, __u64 *out) {
    struct nsproxy *nsproxy = BPF_CORE_READ(task, nsproxy);
    if (!nsproxy)
        return ERR_CODE;

    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
    if (!mnt_ns)
        return ERR_CODE;

    __u64 inum = (__u64)BPF_CORE_READ(mnt_ns, ns.inum);
    *out = inum;
    return inum == 0 ? ERR_CODE : 0;
}

static __always_inline int get_pid_ns_id(struct task_struct *task, __u64 *out) {
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct pid         *pid_ptr = BPF_CORE_READ(leader, thread_pid);
    int                 level   = BPF_CORE_READ(pid_ptr, level);

    struct upid target = {};
    bpf_probe_read_kernel(&target, sizeof(target), &pid_ptr->numbers[level]);
    if (!target.ns)
        return ERR_CODE;

    __u64 inum = (__u64)BPF_CORE_READ(target.ns, ns.inum);
    *out = inum;
    return inum == 0 ? ERR_CODE : 0;
}

static __always_inline void fill_process_namespaces(struct task_struct *task,
                                                    struct process_stats *stats) {
    stats->mnt_ns = 0;
    stats->pid_ns = 0;

    get_mnt_ns_id(task, &stats->mnt_ns);
    get_pid_ns_id(task, &stats->pid_ns);
}
