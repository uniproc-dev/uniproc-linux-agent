use crate::vmlinux::in6_addr;
use aya_ebpf::helpers::bpf_probe_read_kernel;

#[inline(always)]
pub fn is_loopback_v4(addr: u32) -> bool {
    (addr & 0x0000_00FF) == 0x7F
}

#[inline(always)]
pub unsafe fn is_loopback_v6(addr: *const in6_addr) -> bool {
    let words: [u32; 4] = match bpf_probe_read_kernel(addr.cast::<[u32; 4]>()) {
        Ok(w) => w,
        Err(_) => return false,
    };
    words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0x0100_0000
}
