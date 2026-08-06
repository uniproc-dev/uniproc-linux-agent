use crate::constants::{NR_ACTIVE_FILE, NR_FREE_PAGES, NR_INACTIVE_FILE, NR_SHMEM, NR_SLAB_RECLAIMABLE_B};
use crate::maps::{MachineStats, KSYM_ADDRS_MAP, SHIFT_MAP};
use aya_ebpf::helpers::bpf_probe_read_kernel;

pub const MEM_UPDATE_INTERVAL_NS: u64 = 1_000_000;

/// atomic_long_t is just a `long` on 64-bit kernels; we only need its
/// counter value.
#[inline(always)]
unsafe fn read_atomic_long(addr: u64) -> i64 {
    bpf_probe_read_kernel(addr as *const i64).unwrap_or(0)
}

/// Approximates si_mem_available() from kernel symbol addresses stored in
/// KSYM_ADDRS_MAP (populated by userspace on load):
///   [0] totalram_pages, [1] vm_zone_stat, [2] vm_node_stat, [3] totalreserve_pages
///
/// NOTE (aya migration): ported 1:1 from mem.h; still relies on the same
/// manual-kallsyms-lookup approach as the libbpf-rs version (aya has no
/// built-in helper for arbitrary kernel-symbol addresses either).
#[inline(always)]
pub unsafe fn update_mem_stats(mem: &mut MachineStats) {
    let shift = match SHIFT_MAP.get(0) {
        Some(s) if *s != 0 => *s,
        _ => return,
    };

    let a0 = KSYM_ADDRS_MAP.get(0).copied().unwrap_or(0);
    let a1 = KSYM_ADDRS_MAP.get(1).copied().unwrap_or(0);
    let a2 = KSYM_ADDRS_MAP.get(2).copied().unwrap_or(0);
    let a3 = KSYM_ADDRS_MAP.get(3).copied().unwrap_or(0);
    if a0 == 0 || a1 == 0 || a2 == 0 || a3 == 0 {
        return;
    }

    const ATOMIC_SIZE: u64 = 8;

    // 1. Total RAM
    let total_pages: u64 = bpf_probe_read_kernel(a0 as *const u64).unwrap_or(0);
    mem.total_kb = total_pages << shift;

    // 2. Free pages (vm_zone_stat[NR_FREE_PAGES])
    let free_pages = read_atomic_long(a1 + (NR_FREE_PAGES as u64) * ATOMIC_SIZE);
    mem.free_kb = if free_pages > 0 { (free_pages as u64) << shift } else { 0 };

    // 3. Reclaimable pages (vm_node_stat)
    let active_file = read_atomic_long(a2 + (NR_ACTIVE_FILE as u64) * ATOMIC_SIZE);
    let inactive_file = read_atomic_long(a2 + (NR_INACTIVE_FILE as u64) * ATOMIC_SIZE);
    let shmem = read_atomic_long(a2 + (NR_SHMEM as u64) * ATOMIC_SIZE);
    let slab_reclaimable = read_atomic_long(a2 + (NR_SLAB_RECLAIMABLE_B as u64) * ATOMIC_SIZE);

    mem.cached_kb = ((active_file + inactive_file + shmem) as u64) << shift;

    // 4. Available memory
    let reserve_pages: u64 = bpf_probe_read_kernel(a3 as *const u64).unwrap_or(0);

    let mut available = free_pages - reserve_pages as i64;
    let reclaimable = active_file + inactive_file + slab_reclaimable;
    let penalty = (reclaimable >> 1).min(reserve_pages as i64);
    available += reclaimable - penalty;

    mem.available_kb = if available > 0 { (available as u64) << shift } else { 0 };
    mem.used_kb = if mem.total_kb > mem.available_kb {
        mem.total_kb - mem.available_kb
    } else {
        0
    };
}
