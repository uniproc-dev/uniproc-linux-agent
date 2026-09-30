// Disk and pipe I/O probes.
//
// Hooks:
//   fexit/vfs_read       — regular files (file read bytes + ops) and FIFOs
//   fexit/vfs_write      — regular files (file write bytes + ops) and FIFOs
//   sys_exit_sendfile64  — bytes sendfile(2) moved
//
// References:
//   https://github.com/microsoft/WSL2-Linux-Kernel/.../include/linux/fs.h#L2026

#include "include/disk.h"
#include <bpf/bpf_tracing.h>

SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, struct file *file, char *buf, size_t count,
             loff_t *pos, ssize_t ret) {
    if (ret <= 0) return 0;
    __u32 pid  = get_pid();
    umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
    switch (mode & S_IFMT) {
        case S_IFREG:
            update_disk_stats(pid, (__u64)ret, TRAFFIC_RX);
            increment_disk_iops(pid, TRAFFIC_RX);
            break;
        case S_IFIFO:
            update_pipe_stats(pid, (__u64)ret, TRAFFIC_RX);
            break;
    }
    return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, struct file *file, const char *buf, size_t count,
             loff_t *pos, ssize_t ret) {
    if (ret <= 0) return 0;
    __u32 pid  = get_pid();
    umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
    switch (mode & S_IFMT) {
        case S_IFREG:
            update_disk_stats(pid, (__u64)ret, TRAFFIC_TX);
            increment_disk_iops(pid, TRAFFIC_TX);
            break;
        case S_IFIFO:
            update_pipe_stats(pid, (__u64)ret, TRAFFIC_TX);
            break;
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendfile64")
int sendfile_exit(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->ret <= 0) return 0;
    add_sendfile_bytes(get_pid(), (__u64)ctx->ret);
    return 0;
}
