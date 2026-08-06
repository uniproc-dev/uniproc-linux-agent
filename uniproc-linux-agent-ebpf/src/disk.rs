// Disk and pipe I/O probes.
//
// Hooks:
//   fexit/vfs_read       — regular files (disk read bytes + IOPS) and FIFOs
//   fexit/vfs_write      — regular files (disk write bytes + IOPS) and FIFOs
//   fexit/vfs_iter_read  — splice/sendfile read path for regular files
//   fexit/vfs_iter_write — splice/sendfile write path for regular files

use crate::common::{
    get_pid, increment_disk_iops, update_disk_stats, update_pipe_stats, TrafficDir,
};
use crate::constants::{S_IFIFO, S_IFMT, S_IFREG};
use crate::vmlinux::file;
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::fexit;
use aya_ebpf::programs::FExitContext;

#[inline(always)]
unsafe fn file_mode(file_ptr: *const file) -> Option<u16> {
    if file_ptr.is_null() {
        return None;
    }
    let inode: *mut crate::vmlinux::inode =
        bpf_probe_read_kernel(&(*file_ptr).f_inode as *const *mut crate::vmlinux::inode).ok()?;
    if inode.is_null() {
        return None;
    }
    bpf_probe_read_kernel(&(*inode).i_mode as *const u16).ok()
}

#[fexit(function = "vfs_read")]
pub fn vfs_read_exit(ctx: FExitContext) -> i32 {
    match unsafe { try_vfs_read_exit(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_vfs_read_exit(ctx: FExitContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(4);
    if ret <= 0 {
        return Ok(0);
    }
    let file_ptr: *const file = ctx.arg(0);
    let pid = get_pid();
    if let Some(mode) = file_mode(file_ptr) {
        match mode & S_IFMT {
            S_IFREG => {
                update_disk_stats(pid, ret as u64, TrafficDir::Rx);
                increment_disk_iops(pid, TrafficDir::Rx);
            }
            S_IFIFO => update_pipe_stats(pid, ret as u64, TrafficDir::Rx),
            _ => {}
        }
    }
    Ok(0)
}

#[fexit(function = "vfs_write")]
pub fn vfs_write_exit(ctx: FExitContext) -> i32 {
    match unsafe { try_vfs_write_exit(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_vfs_write_exit(ctx: FExitContext) -> Result<i32, i32> {
    let ret: i64 = ctx.arg(4);
    if ret <= 0 {
        return Ok(0);
    }
    let file_ptr: *const file = ctx.arg(0);
    let pid = get_pid();
    if let Some(mode) = file_mode(file_ptr) {
        match mode & S_IFMT {
            S_IFREG => {
                update_disk_stats(pid, ret as u64, TrafficDir::Tx);
                increment_disk_iops(pid, TrafficDir::Tx);
            }
            S_IFIFO => update_pipe_stats(pid, ret as u64, TrafficDir::Tx),
            _ => {}
        }
    }
    Ok(0)
}

#[fexit(function = "vfs_iter_read")]
pub fn vfs_iter_read_exit(ctx: FExitContext) -> i32 {
    match unsafe { try_vfs_iter_exit(ctx, TrafficDir::Rx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[fexit(function = "vfs_iter_write")]
pub fn vfs_iter_write_exit(ctx: FExitContext) -> i32 {
    match unsafe { try_vfs_iter_exit(ctx, TrafficDir::Tx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_vfs_iter_exit(ctx: FExitContext, dir: TrafficDir) -> Result<i32, i32> {
    // fn(file: &File, iter: &iov_iter, ppos: *mut loff_t, flags: u32) -> ssize_t
    let ret: i64 = ctx.arg(4);
    if ret <= 0 {
        return Ok(0);
    }
    let file_ptr: *const file = ctx.arg(0);
    if let Some(mode) = file_mode(file_ptr) {
        if mode & S_IFMT == S_IFREG {
            update_disk_stats(get_pid(), ret as u64, dir);
        }
    }
    Ok(0)
}
