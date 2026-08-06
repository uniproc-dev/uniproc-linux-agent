#![allow(dead_code)]

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const AF_VSOCK: u16 = 40;

pub const SOCK_STREAM: u16 = 1;
pub const SOCK_DGRAM: u16 = 2;

pub const IPPROTO_TCP: u16 = 6;
pub const IPPROTO_UDP: u16 = 17;

pub const S_IFMT: u16 = 0o170000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFIFO: u16 = 0o010000;

// mm rss_stat indices (include/linux/mm_types_task.h)
pub const MM_FILEPAGES: usize = 0;
pub const MM_ANONPAGES: usize = 1;
pub const MM_SHMEMPAGES: usize = 3;

// vm_zone_stat / vm_node_stat item indices (mm/vmstat.c enums), matching the
// original constants.h values used by mem.h's si_mem_available() port.
// NOTE: these must match this kernel's `enum zone_stat_item` /
// `enum node_stat_item` (mm/vmstat.c); read from this machine's live BTF
// dump (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`) rather
// than assumed, since they are not guaranteed stable across kernel versions.
pub const NR_FREE_PAGES: usize = 0;
pub const NR_INACTIVE_FILE: usize = 2;
pub const NR_ACTIVE_FILE: usize = 3;
pub const NR_SLAB_RECLAIMABLE_B: usize = 5;
pub const NR_SHMEM: usize = 22;
