#pragma once

#include "vmlinux.h"
#include "maps.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define MM_FILEPAGES  0
#define MM_ANONPAGES  1
#define MM_SHMEMPAGES 3

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

static __always_inline void update_process_metrics(__u32 pid, __u64 runtime) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    __u32 flags = BPF_CORE_READ(task, flags);
    if (flags & 0x00200000) return; // skip kernel threads

    __u32 local_pid = 0;
    if (get_local_tgid(task, &local_pid) < 0 || local_pid == 0) return;

    struct process_stats *stats = bpf_map_lookup_elem(&process_stats_map, &pid);
    if (!stats) return;

    stats->cpu_runtime_ns += runtime;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return;

    __u32 key = 0;
    __u32 *shift_ptr = bpf_map_lookup_elem(&shift_map, &key);
    if (!shift_ptr) return;
    __u32 shift = *shift_ptr;

    __s64 pages = 0;
    int rss_idxs[3] = { MM_FILEPAGES, MM_ANONPAGES, MM_SHMEMPAGES };
    for (int i = 0; i < 3; i++) {
        __s64 count = 0;
        bpf_probe_read_kernel(&count, sizeof(count),
            &mm->rss_stat[rss_idxs[i]].count);
        if (count > 0) pages += count;
    }

    stats->rss_kb = pages > 0 ? ((__u64)pages << shift) : 0;
}
