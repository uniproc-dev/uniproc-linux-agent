#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define RECORD_THREAD  1
#define RECORD_PROCESS 2

#define PF_KTHREAD 0x00200000
#define MM_SWAPENTS 2

struct thread_counters {
    __u64 utime;
    __u64 stime;
    __u64 runtime;
    __u64 nvcsw;
    __u64 nivcsw;
    __u64 min_flt;
    __u64 maj_flt;
    __u64 rchar;
    __u64 wchar;
    __u64 syscr;
    __u64 syscw;
    __u64 read_bytes;
    __u64 write_bytes;
};

struct thread_record {
    __u32 kind;
    __u32 tgid;
    struct thread_counters counters;
};

struct process_record {
    __u32 kind;
    __u32 tgid;
    __u32 ppid;
    __u32 local_pid;
    __u64 start_boottime;
    __u64 exec_id;
    __u64 mnt_ns;
    __u64 pid_ns;
    struct thread_counters exited;
    __u64 rss_file;
    __u64 rss_anon;
    __u64 rss_shmem;
    __u64 swap;
    __u64 hiwater_rss;
    __u64 total_vm;
    __u64 hiwater_vm;
    __u32 threads;
    __u32 state;
    __u32 exit_state;
    __s32 static_prio;
    __u32 policy;
    __u32 rt_priority;
    __u32 uid;
    __u32 view_pid;
    char comm[16];
};
