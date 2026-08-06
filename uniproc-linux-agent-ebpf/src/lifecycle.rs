use crate::maps::{ProcessStats, PROCESS_STATS_MAP};
use crate::process::{fill_process_namespaces, get_local_tgid};
use crate::vmlinux::task_struct;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel};
use aya_ebpf::macros::{kprobe, tracepoint};
use aya_ebpf::programs::{ProbeContext, TracePointContext};

#[tracepoint]
pub fn handle_exec(_ctx: TracePointContext) -> u32 {
    unsafe {
        let task = bpf_get_current_task() as *mut task_struct;
        let pid_tgid = bpf_get_current_pid_tgid();
        let tgid = (pid_tgid >> 32) as u32;

        let local_pid = get_local_tgid(task).unwrap_or(0);

        if let Some(existing) = PROCESS_STATS_MAP.get_ptr_mut(&tgid) {
            let s: &mut ProcessStats = &mut *existing;
            s.global_pid = tgid;
            s.local_pid = local_pid;
            fill_process_namespaces(task, s);
        } else {
            let mut new_stats = core::mem::zeroed::<ProcessStats>();
            new_stats.global_pid = tgid;
            new_stats.local_pid = local_pid;
            fill_process_namespaces(task, &mut new_stats);
            let _ = PROCESS_STATS_MAP.insert(&tgid, &new_stats, aya_ebpf::bindings::BPF_ANY as u64);
        }
    }
    0
}

#[tracepoint]
pub fn handle_exit(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if pid == tgid {
        let _ = PROCESS_STATS_MAP.remove(&tgid);
    }
    0
}

#[kprobe]
pub fn handle_new_task(ctx: ProbeContext) -> u32 {
    unsafe { try_handle_new_task(ctx) }.unwrap_or(0)
}

unsafe fn try_handle_new_task(ctx: ProbeContext) -> Option<u32> {
    let p: *mut task_struct = ctx.arg(0)?;

    let pid: i32 = bpf_probe_read_kernel(&(*p).pid as *const _).ok()?;
    let tgid: i32 = bpf_probe_read_kernel(&(*p).tgid as *const _).ok()?;
    if pid != tgid {
        return Some(0);
    }

    let mm: *mut core::ffi::c_void =
        bpf_probe_read_kernel(&(*p).mm as *const _ as *const *mut core::ffi::c_void).ok()?;
    if mm.is_null() {
        return Some(0);
    }

    let local_pid = get_local_tgid(p).unwrap_or(0);
    let mut new_stats = core::mem::zeroed::<ProcessStats>();
    new_stats.global_pid = tgid as u32;
    new_stats.local_pid = local_pid;
    fill_process_namespaces(p, &mut new_stats);
    let _ = PROCESS_STATS_MAP.insert(&(tgid as u32), &new_stats, aya_ebpf::bindings::BPF_NOEXIST as u64);
    Some(0)
}
