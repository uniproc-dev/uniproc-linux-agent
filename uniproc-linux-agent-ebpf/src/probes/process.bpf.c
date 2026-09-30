#include "include/process.h"
#include <bpf/bpf_tracing.h>

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = (__u32)(pid_tgid >> 32);

    __u32 local_pid = 0;
    get_local_tgid(task, &local_pid);

    struct process_stats *s = bpf_map_lookup_elem(&process_stats_map, &tgid);
    if (s) {
        s->global_pid = tgid;
        s->local_pid  = local_pid;
        fill_process_namespaces(task, s);
    } else {
        struct process_stats new_stats = {
            .global_pid = tgid,
            .local_pid  = local_pid,
        };
        fill_process_namespaces(task, &new_stats);

        insert_process_stats(tgid, &new_stats, BPF_ANY);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid);
    __u32 tgid = (__u32)(pid_tgid >> 32);

    if (pid == tgid)
        bpf_map_delete_elem(&process_stats_map, &tgid);

    return 0;
}

SEC("fentry/wake_up_new_task")
int BPF_PROG(handle_new_task, struct task_struct *p) {
    __u32 pid  = BPF_CORE_READ(p, pid);
    __u32 tgid = BPF_CORE_READ(p, tgid);

    if (pid != tgid) return 0;

    if (!BPF_CORE_READ(p, mm)) return 0;

    __u32 local_pid = 0;
    get_local_tgid(p, &local_pid);

    struct process_stats new_stats = {
        .global_pid = tgid,
        .local_pid  = local_pid,
    };
    fill_process_namespaces(p, &new_stats);
    insert_process_stats(tgid, &new_stats, BPF_NOEXIST);
    return 0;
}
