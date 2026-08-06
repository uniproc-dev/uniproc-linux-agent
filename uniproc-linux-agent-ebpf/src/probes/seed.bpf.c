#include "include/process.h"

SEC("iter/task")
int seed_processes(struct bpf_iter__task *ctx) {
    struct task_struct *task = ctx->task;

    if (!task) return 0;

    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    if (task != leader) return 0;

    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (!mm) return 0;

    __u32 tgid = (__u32)BPF_CORE_READ(task, tgid);
    if (tgid == 0) return 0;

    struct process_stats new_stats = {
        .global_pid = tgid,
        .local_pid  = 0,
    };

    get_local_tgid(task, &new_stats.local_pid);
    fill_process_namespaces(task, &new_stats);

    bpf_map_update_elem(&process_stats_map, &tgid, &new_stats, BPF_NOEXIST);

    bpf_seq_write(ctx->meta->seq, &tgid, sizeof(tgid));
    return 0;
}

SEC("iter/task")
int task_names(struct bpf_iter__task *ctx) {
    struct task_struct *task = ctx->task;
    if (!task) return 0;
    if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid)) return 0;
    if (!BPF_CORE_READ(task, mm)) return 0;

    __u32 tgid      = BPF_CORE_READ(task, tgid);
    __u64 start_time = BPF_CORE_READ(task, start_time);
    char path[64] = {};

    struct mm_struct *mm = task->mm;
    if (!mm) return 0;

    struct file *exe = mm->exe_file;
    if (exe)
        bpf_d_path(&exe->f_path, path, sizeof(path));

    bpf_seq_write(ctx->meta->seq, &tgid,       sizeof(tgid));
    bpf_seq_write(ctx->meta->seq, &start_time, sizeof(start_time));
    bpf_seq_write(ctx->meta->seq, path,        sizeof(path));
    return 0;
}

SEC("iter/task")
int list_processes(struct bpf_iter__task *ctx) {
    struct task_struct *task = ctx->task;
    if (!task) return 0;

    if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid)) return 0;

    if (!BPF_CORE_READ(task, mm)) return 0;

    __u32 tgid = BPF_CORE_READ(task, tgid);
    bpf_seq_write(ctx->meta->seq, &tgid, sizeof(tgid));
    return 0;
}
