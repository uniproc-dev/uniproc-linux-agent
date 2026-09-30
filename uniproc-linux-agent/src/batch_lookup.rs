use crate::probes::RawProcessStats;
use libbpf_rs::MapCore;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;

const BPF_MAP_LOOKUP_BATCH: i64 = 24;

pub struct BatchLookup {
    keys_buf: Vec<[u8; 4]>,
    values_buf: Vec<[u8; size_of::<RawProcessStats>()]>,
    out_buf: Vec<RawProcessStats>,
}

impl BatchLookup {
    pub fn new() -> Self {
        Self {
            keys_buf: Vec::new(),
            values_buf: Vec::new(),
            out_buf: Vec::new(),
        }
    }

    pub fn lookup(&mut self, map: &impl MapCore) -> anyhow::Result<&[RawProcessStats]> {
        let map_fd = map.as_fd().as_raw_fd();

        let cap = (map.max_entries() as usize).next_power_of_two();
        if self.keys_buf.len() < cap {
            self.keys_buf.resize(cap, [0u8; 4]);
            self.values_buf
                .resize(cap, [0u8; size_of::<RawProcessStats>()]);
        }

        self.out_buf.clear();

        #[repr(C, align(8))]
        struct BatchAttr {
            in_batch: u64,
            out_batch: u64,
            keys: u64,
            values: u64,
            count: u32,
            map_fd: u32,
            elem_flags: u64,
            flags: u64,
            _pad: [u8; 64],
        }

        let mut out_batch = [0u8; 4];
        let mut in_batch_ptr: u64 = 0;

        loop {
            // NOTE: the kernel writes `count` (and `out_batch`) back into this
            // struct, so it must be a `mut` binding handed over as a `*mut`
            // pointer - otherwise reading `attr.count` after the syscall reads
            // a value the optimiser is entitled to treat as unchanged.
            let mut attr = BatchAttr {
                in_batch: in_batch_ptr,
                out_batch: out_batch.as_mut_ptr() as u64,
                keys: self.keys_buf.as_mut_ptr() as u64,
                values: self.values_buf.as_mut_ptr() as u64,
                count: self.keys_buf.len() as u32,
                map_fd: map_fd as u32,
                elem_flags: 0,
                flags: 0,
                _pad: [0; 64],
            };

            let ret = unsafe {
                libc::syscall(
                    libc::SYS_bpf,
                    BPF_MAP_LOOKUP_BATCH,
                    &mut attr as *mut _ as *mut libc::c_void,
                    size_of::<BatchAttr>() as u32,
                )
            };

            for value in &self.values_buf[..attr.count as usize] {
                self.out_buf.push(unsafe {
                    std::ptr::read_unaligned(value.as_ptr() as *const RawProcessStats)
                });
            }

            if ret == 0 {
                break;
            }

            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::ENOENT) => break,
                Some(libc::EFAULT) => {
                    let new_cap = self.keys_buf.len() * 2;
                    self.keys_buf.resize(new_cap, [0u8; 4]);
                    self.values_buf
                        .resize(new_cap, [0u8; size_of::<RawProcessStats>()]);
                    in_batch_ptr = 0;
                    self.out_buf.clear();
                    continue;
                }
                _ => return Err(e.into()),
            }
        }

        Ok(&self.out_buf)
    }
}
