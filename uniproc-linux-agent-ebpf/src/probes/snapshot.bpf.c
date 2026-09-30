#include "include/process.h"
#include "include/snapshot.h"

const volatile __u64 agent_pid_ns = 0;

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct process_record);
} snapshot_scratch SEC(".maps");

static __always_inline __u32 pid_in_agent_ns(struct task_struct *task) {
    struct pid *pid_ptr = BPF_CORE_READ(task, thread_pid);
    unsigned int level = BPF_CORE_READ(pid_ptr, level);
    for (int i = 0; i < 8; i++) {
        if (i > level) break;
        struct upid up = {};
        bpf_probe_read_kernel(&up, sizeof(up), &pid_ptr->numbers[i]);
        if (up.ns && BPF_CORE_READ(up.ns, ns.inum) == agent_pid_ns)
            return up.nr;
    }
    return 0;
}

static __always_inline void read_thread(struct task_struct *task, struct thread_counters *c) {
    c->utime   = BPF_CORE_READ(task, utime);
    c->stime   = BPF_CORE_READ(task, stime);
    c->runtime = BPF_CORE_READ(task, se.sum_exec_runtime);
    c->nvcsw   = BPF_CORE_READ(task, nvcsw);
    c->nivcsw  = BPF_CORE_READ(task, nivcsw);
    c->min_flt = BPF_CORE_READ(task, min_flt);
    c->maj_flt = BPF_CORE_READ(task, maj_flt);
    c->rchar       = BPF_CORE_READ(task, ioac.rchar);
    c->wchar       = BPF_CORE_READ(task, ioac.wchar);
    c->syscr       = BPF_CORE_READ(task, ioac.syscr);
    c->syscw       = BPF_CORE_READ(task, ioac.syscw);
    c->read_bytes  = BPF_CORE_READ(task, ioac.read_bytes);
    c->write_bytes = BPF_CORE_READ(task, ioac.write_bytes);
}

static __always_inline void read_exited(struct signal_struct *sig, struct thread_counters *c) {
    c->utime   = BPF_CORE_READ(sig, utime);
    c->stime   = BPF_CORE_READ(sig, stime);
    c->runtime = BPF_CORE_READ(sig, sum_sched_runtime);
    c->nvcsw   = BPF_CORE_READ(sig, nvcsw);
    c->nivcsw  = BPF_CORE_READ(sig, nivcsw);
    c->min_flt = BPF_CORE_READ(sig, min_flt);
    c->maj_flt = BPF_CORE_READ(sig, maj_flt);
    c->rchar       = BPF_CORE_READ(sig, ioac.rchar);
    c->wchar       = BPF_CORE_READ(sig, ioac.wchar);
    c->syscr       = BPF_CORE_READ(sig, ioac.syscr);
    c->syscw       = BPF_CORE_READ(sig, ioac.syscw);
    c->read_bytes  = BPF_CORE_READ(sig, ioac.read_bytes);
    c->write_bytes = BPF_CORE_READ(sig, ioac.write_bytes);
}

static __always_inline __u64 rss_pages(struct mm_struct *mm, int idx) {
    __s64 count = 0;
    bpf_probe_read_kernel(&count, sizeof(count), &mm->rss_stat[idx].count);
    return count > 0 ? (__u64)count : 0;
}

SEC("iter/task")
int task_snapshot(struct bpf_iter__task *ctx) {
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    if (!task) return 0;

    if (BPF_CORE_READ(task, flags) & PF_KTHREAD) return 0;

    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct mm_struct *mm = BPF_CORE_READ(leader, mm);
    if (!mm) return 0;

    __u32 tgid = BPF_CORE_READ(task, tgid);

    __u32 zero = 0;
    struct process_record *p = bpf_map_lookup_elem(&snapshot_scratch, &zero);
    if (task == leader && p) {
        __builtin_memset(p, 0, sizeof(*p));
        p->kind = RECORD_PROCESS;
        p->tgid = tgid;
        p->ppid = BPF_CORE_READ(task, real_parent, tgid);
        get_local_tgid(task, &p->local_pid);
        p->view_pid = pid_in_agent_ns(task);
        p->start_boottime = BPF_CORE_READ(task, start_boottime);
        p->exec_id = BPF_CORE_READ(task, self_exec_id);
        get_mnt_ns_id(task, &p->mnt_ns);
        get_pid_ns_id(task, &p->pid_ns);

        struct signal_struct *sig = BPF_CORE_READ(task, signal);
        read_exited(sig, &p->exited);
        p->threads = BPF_CORE_READ(sig, nr_threads);

        p->rss_file    = rss_pages(mm, MM_FILEPAGES);
        p->rss_anon    = rss_pages(mm, MM_ANONPAGES);
        p->rss_shmem   = rss_pages(mm, MM_SHMEMPAGES);
        p->swap        = rss_pages(mm, MM_SWAPENTS);
        p->hiwater_rss = BPF_CORE_READ(mm, hiwater_rss);
        p->total_vm    = BPF_CORE_READ(mm, total_vm);
        p->hiwater_vm  = BPF_CORE_READ(mm, hiwater_vm);

        p->state       = BPF_CORE_READ(task, __state);
        p->exit_state  = BPF_CORE_READ(task, exit_state);
        p->static_prio = BPF_CORE_READ(task, static_prio);
        p->policy      = BPF_CORE_READ(task, policy);
        p->rt_priority = BPF_CORE_READ(task, rt_priority);
        p->uid         = BPF_CORE_READ(task, real_cred, uid.val);
        BPF_CORE_READ_STR_INTO(&p->comm, task, comm);
        const char *cgroup = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
        if (cgroup)
            bpf_probe_read_kernel_str(p->cgroup, sizeof(p->cgroup), cgroup);

        bpf_seq_write(seq, p, sizeof(*p));
    }

    struct thread_record t = {};
    t.kind = RECORD_THREAD;
    t.tgid = tgid;
    read_thread(task, &t.counters);
    bpf_seq_write(seq, &t, sizeof(t));
    return 0;
}
