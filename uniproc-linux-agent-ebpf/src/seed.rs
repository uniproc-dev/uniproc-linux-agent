// bpf_iter/task programs: seed_processes, task_names, list_processes.
//
// NOTE (aya migration — KNOWN GAP): aya-ebpf's macro crate (aya-ebpf-macros)
// has no `#[iter]`/bpf_iter attribute (confirmed against the current
// aya-ebpf-macros source: kprobe/kretprobe/uprobe/tracepoint/fentry/fexit/
// raw_tracepoint/lsm/... are all present, "iter" is not). aya's *userspace*
// loader (aya-obj) does still recognize the "iter" / "iter.s" ELF section
// prefix when parsing a compiled object, and `aya::programs::Iter` can load
// and attach such a program from userspace — so a hand-rolled program using
// the raw `#[unsafe(no_mangle)] #[unsafe(link_section = "iter/task")]`
// convention below *should* be picked up the same way SEC("iter/task") is
// picked up from the C build. This has not been used in aya-ebpf before to
// our knowledge; it is the highest-risk, least-precedented part of this
// migration and is exactly the kind of case flagged in the task instructions
// as worth trying hard but documenting clearly if it turns out not to work
// end-to-end (e.g. if BTF for the context type can't be resolved because
// this function wasn't produced through the macro's codegen path).
use crate::maps::PROCESS_STATS_MAP;
use crate::process::{fill_process_namespaces, get_local_tgid};
use crate::vmlinux::{bpf_iter__task, task_struct};
use aya_ebpf::helpers::{bpf_d_path, bpf_probe_read_kernel, bpf_seq_write};

#[inline(always)]
unsafe fn ctx_task(ctx: *mut bpf_iter__task) -> *mut task_struct {
    (*ctx).__bindgen_anon_2.task
}

#[inline(always)]
unsafe fn ctx_seq(ctx: *mut bpf_iter__task) -> *mut aya_ebpf::bindings::seq_file {
    let meta = (*ctx).__bindgen_anon_1.meta;
    if meta.is_null() {
        core::ptr::null_mut()
    } else {
        (*meta).__bindgen_anon_1.seq as *mut _
    }
}

#[inline(always)]
unsafe fn seq_write<T>(seq: *mut aya_ebpf::bindings::seq_file, val: &T) {
    if seq.is_null() {
        return;
    }
    bpf_seq_write(
        seq,
        val as *const T as *const core::ffi::c_void,
        core::mem::size_of::<T>() as u32,
    );
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "iter/task")]
pub extern "C" fn seed_processes(ctx: *mut bpf_iter__task) -> i32 {
    unsafe {
        let task = ctx_task(ctx);
        if task.is_null() {
            return 0;
        }
        let leader: *mut task_struct = match bpf_probe_read_kernel(&(*task).group_leader as *const _) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        if task != leader {
            return 0;
        }
        let mm: *mut core::ffi::c_void = match bpf_probe_read_kernel(&(*task).mm as *const _ as *const *mut core::ffi::c_void) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        if mm.is_null() {
            return 0;
        }
        let tgid: i32 = bpf_probe_read_kernel(&(*task).tgid as *const _).unwrap_or(0);
        let tgid = tgid as u32;
        if tgid == 0 {
            return 0;
        }

        let mut stats = core::mem::zeroed::<crate::maps::ProcessStats>();
        stats.global_pid = tgid;
        stats.local_pid = get_local_tgid(task).unwrap_or(0);
        fill_process_namespaces(task, &mut stats);

        let _ = PROCESS_STATS_MAP.insert(&tgid, &stats, aya_ebpf::bindings::BPF_NOEXIST as u64);

        seq_write(ctx_seq(ctx), &tgid);
    }
    0
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "iter/task")]
pub extern "C" fn task_names(ctx: *mut bpf_iter__task) -> i32 {
    unsafe {
        let task = ctx_task(ctx);
        if task.is_null() {
            return 0;
        }
        // NOTE (aya migration): bpf_d_path() requires the kernel verifier to
        // still see a *trusted*/BTF-typed pointer chain by the time it
        // reaches the helper call. Going through bpf_probe_read_kernel()
        // (an opaque helper call) for the intermediate mm/exe_file hops
        // erases that trust and the verifier rejects the program
        // ("R1 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_"). The
        // fix is to keep the whole task->mm->exe_file->f_path chain as
        // plain pointer dereferences (which the verifier is able to follow
        // as direct/trusted BTF struct access on this kernel, since
        // aya-ebpf/bpf-linker emit BTF for these types) instead of routing
        // it through bpf_probe_read_kernel like every other read in this
        // file. This is a real, kernel-verifier-driven behavior difference
        // from the libbpf/BPF_CORE_READ version and is worth flagging: it
        // means "when in doubt use bpf_probe_read_kernel" (safe default
        // everywhere else in this port) is actually wrong for
        // trusted-pointer-consuming helpers like bpf_d_path.
        let pid = (*task).pid;
        let tgid = (*task).tgid;
        if pid != tgid {
            return 0;
        }
        let mm = (*task).mm;
        if mm.is_null() {
            return 0;
        }

        let start_time: u64 = bpf_probe_read_kernel(&(*task).start_time as *const _).unwrap_or(0);
        let mut path_buf = [0u8; 64];

        let exe_file = (*mm).__bindgen_anon_1.exe_file;
        if !exe_file.is_null() {
            let f_path = &mut (*exe_file).__bindgen_anon_1.f_path as *mut crate::vmlinux::path;
            bpf_d_path(
                f_path.cast(),
                path_buf.as_mut_ptr() as *mut core::ffi::c_char,
                path_buf.len() as u32,
            );
        }

        let seq = ctx_seq(ctx);
        let tgid_u = tgid as u32;
        seq_write(seq, &tgid_u);
        seq_write(seq, &start_time);
        seq_write(seq, &path_buf);
    }
    0
}

#[unsafe(no_mangle)]
#[unsafe(link_section = "iter/task")]
pub extern "C" fn list_processes(ctx: *mut bpf_iter__task) -> i32 {
    unsafe {
        let task = ctx_task(ctx);
        if task.is_null() {
            return 0;
        }
        let pid: i32 = bpf_probe_read_kernel(&(*task).pid as *const _).unwrap_or(-1);
        let tgid: i32 = bpf_probe_read_kernel(&(*task).tgid as *const _).unwrap_or(-2);
        if pid != tgid {
            return 0;
        }
        let mm: *mut core::ffi::c_void = match bpf_probe_read_kernel(&(*task).mm as *const _ as *const *mut core::ffi::c_void) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        if mm.is_null() {
            return 0;
        }
        let tgid_u = tgid as u32;
        seq_write(ctx_seq(ctx), &tgid_u);
    }
    0
}
