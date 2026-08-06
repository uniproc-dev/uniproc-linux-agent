use crate::maps::{MachineStats, LAST_MEM_UPDATE_MAP, MACHINE_STATS_MAP};
use crate::mem::{update_mem_stats, MEM_UPDATE_INTERVAL_NS};
use crate::process::update_process_metrics;
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns};
use aya_ebpf::macros::tracepoint;
use aya_ebpf::programs::TracePointContext;

// sched:sched_stat_runtime tracepoint format (this kernel, verified via
// /sys/kernel/tracing/events/sched/sched_stat_runtime/format):
//   offset 0..8:  common header
//   offset 8:     __data_loc comm (4 bytes)
//   offset 12:    pid_t pid (4 bytes)
//   offset 16:    u64 runtime
const RUNTIME_OFFSET: usize = 16;

#[tracepoint]
pub fn global_cpu_monitor(ctx: TracePointContext) -> u32 {
    unsafe { try_global_cpu_monitor(ctx) }.unwrap_or(0)
}

unsafe fn try_global_cpu_monitor(ctx: TracePointContext) -> Option<u32> {
    let runtime: u64 = ctx.read_at(RUNTIME_OFFSET).ok()?;
    let now = bpf_ktime_get_ns();
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;

    update_process_metrics(pid, runtime);

    let ms = MACHINE_STATS_MAP.get_ptr_mut(0)?;
    let ms: &mut MachineStats = &mut *ms;
    ms.busy_ns += runtime;
    ms.last_tsc = now;

    if let Some(last_update) = LAST_MEM_UPDATE_MAP.get_ptr_mut(0) {
        let last_update = &mut *last_update;
        if now - *last_update >= MEM_UPDATE_INTERVAL_NS {
            update_mem_stats(ms);
            *last_update = now;
        }
    }

    Some(0)
}
