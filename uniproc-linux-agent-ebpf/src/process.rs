use crate::common::ERR_CODE;
use crate::maps::{ProcessStats, PROCESS_STATS_MAP, SHIFT_MAP};
use crate::vmlinux::{mm_struct, mnt_namespace, nsproxy, pid, task_struct, upid};
use aya_ebpf::helpers::{bpf_get_current_task, bpf_probe_read_kernel};

const MM_FILEPAGES: usize = 0;
const MM_ANONPAGES: usize = 1;
const MM_SHMEMPAGES: usize = 3;

/// NOTE (aya migration): the original C code used BPF_CORE_READ(), which
/// relies on libbpf/clang CO-RE relocations to stay portable across kernel
/// builds whose struct layouts differ. aya-ebpf does not provide an
/// equivalent automatic-relocation macro; these reads are plain
/// bpf_probe_read_kernel() calls against struct layouts generated once
/// (via `aya-tool generate`) from this machine's live BTF
/// (/sys/kernel/btf/vmlinux). They will work on this kernel but, unlike the
/// libbpf-rs version, are NOT CO-RE portable to a differently-built kernel
/// without regenerating vmlinux.rs. This is a known behavior gap - see the
/// migration report. It also means the dev machine's kernel version matters:
/// this build was generated against a kernel where mm_struct::rss_stat is an
/// array of `percpu_counter` (newer kernel API) rather than the plain atomic
/// counters the original WSL2-targeted C code assumed - ported below using
/// percpu_counter's approximate `.count` fast-path field.
#[inline(always)]
pub unsafe fn get_local_tgid(task: *mut task_struct) -> Result<u32, i64> {
    let leader: *mut task_struct =
        bpf_probe_read_kernel(&(*task).group_leader as *const *mut task_struct).map_err(|_| ERR_CODE)?;
    if leader.is_null() {
        return Err(ERR_CODE);
    }
    let pid_ptr: *mut pid =
        bpf_probe_read_kernel(&(*leader).thread_pid as *const *mut pid).map_err(|_| ERR_CODE)?;
    if pid_ptr.is_null() {
        return Err(ERR_CODE);
    }
    let level: u32 = bpf_probe_read_kernel(&(*pid_ptr).level as *const u32).map_err(|_| ERR_CODE)?;

    let entry: upid =
        bpf_probe_read_kernel((*pid_ptr).numbers.as_ptr().add(level as usize)).map_err(|_| ERR_CODE)?;
    let mut nr = entry.nr as u32;

    if nr == 0 {
        let tgid: i32 = bpf_probe_read_kernel(&(*leader).tgid as *const i32).map_err(|_| ERR_CODE)?;
        nr = tgid as u32;
    }

    if nr == 0 {
        Err(ERR_CODE)
    } else {
        Ok(nr)
    }
}

#[inline(always)]
pub unsafe fn get_mnt_ns_id(task: *mut task_struct) -> Result<u64, i64> {
    let nsproxy: *mut nsproxy =
        bpf_probe_read_kernel(&(*task).nsproxy as *const *mut nsproxy).map_err(|_| ERR_CODE)?;
    if nsproxy.is_null() {
        return Err(ERR_CODE);
    }
    let mnt_ns: *mut mnt_namespace =
        bpf_probe_read_kernel(&(*nsproxy).mnt_ns as *const *mut mnt_namespace).map_err(|_| ERR_CODE)?;
    if mnt_ns.is_null() {
        return Err(ERR_CODE);
    }
    let inum: u32 =
        bpf_probe_read_kernel(&(*mnt_ns).ns.inum as *const u32).map_err(|_| ERR_CODE)?;
    if inum == 0 {
        Err(ERR_CODE)
    } else {
        Ok(inum as u64)
    }
}

#[inline(always)]
pub unsafe fn get_pid_ns_id(task: *mut task_struct) -> Result<u64, i64> {
    let leader: *mut task_struct =
        bpf_probe_read_kernel(&(*task).group_leader as *const *mut task_struct).map_err(|_| ERR_CODE)?;
    let pid_ptr: *mut pid =
        bpf_probe_read_kernel(&(*leader).thread_pid as *const *mut pid).map_err(|_| ERR_CODE)?;
    let level: u32 = bpf_probe_read_kernel(&(*pid_ptr).level as *const u32).map_err(|_| ERR_CODE)?;
    let entry: upid =
        bpf_probe_read_kernel((*pid_ptr).numbers.as_ptr().add(level as usize)).map_err(|_| ERR_CODE)?;
    if entry.ns.is_null() {
        return Err(ERR_CODE);
    }
    let inum: u32 =
        bpf_probe_read_kernel(&(*entry.ns).ns.inum as *const u32).map_err(|_| ERR_CODE)?;
    if inum == 0 {
        Err(ERR_CODE)
    } else {
        Ok(inum as u64)
    }
}

#[inline(always)]
pub unsafe fn fill_process_namespaces(task: *mut task_struct, stats: &mut ProcessStats) {
    stats.mnt_ns = get_mnt_ns_id(task).unwrap_or(0);
    stats.pid_ns = get_pid_ns_id(task).unwrap_or(0);
}

#[inline(always)]
pub unsafe fn update_process_metrics(pid: u32, runtime: u64) {
    let task = bpf_get_current_task() as *mut task_struct;

    let flags: u32 = match bpf_probe_read_kernel(&(*task).flags as *const u32) {
        Ok(f) => f,
        Err(_) => return,
    };
    if flags & 0x0020_0000 != 0 {
        return; // skip kernel threads
    }

    let local_pid = match get_local_tgid(task) {
        Ok(v) if v != 0 => v,
        _ => return,
    };
    let _ = local_pid;

    let stats = match PROCESS_STATS_MAP.get_ptr_mut(&pid) {
        Some(p) => &mut *p,
        None => return,
    };
    stats.cpu_runtime_ns += runtime;

    let mm: *mut mm_struct = match bpf_probe_read_kernel(&(*task).mm as *const *mut mm_struct) {
        Ok(v) => v,
        Err(_) => return,
    };
    if mm.is_null() {
        return;
    }

    let shift = match SHIFT_MAP.get(0) {
        Some(s) => *s,
        None => return,
    };

    let idxs = [MM_FILEPAGES, MM_ANONPAGES, MM_SHMEMPAGES];
    let mut pages: i64 = 0;
    for idx in idxs {
        let count: i64 =
            bpf_probe_read_kernel(&(*mm).__bindgen_anon_1.rss_stat[idx].count as *const i64)
                .unwrap_or(0);
        if count > 0 {
            pages += count;
        }
    }

    stats.rss_kb = if pages > 0 { (pages as u64) << shift } else { 0 };
}
