use crate::probes::RawProcessStats;
use libbpf_rs::MapCore;
use std::io;
use std::mem::size_of;
use std::os::fd::AsRawFd;

const BPF_MAP_LOOKUP_BATCH: i64 = 24;
const CHUNK: usize = 1024;

pub struct BatchLookup {
    keys_buf: Vec<[u8; 4]>,
    values_buf: Vec<[u8; size_of::<RawProcessStats>()]>,
    out_buf: Vec<RawProcessStats>,
}

impl BatchLookup {
    pub fn new() -> Self {
        Self {
            keys_buf: vec![[0u8; 4]; CHUNK],
            values_buf: vec![[0u8; size_of::<RawProcessStats>()]; CHUNK],
            out_buf: Vec::new(),
        }
    }

    pub fn lookup(&mut self, map: &impl MapCore) -> anyhow::Result<&[RawProcessStats]> {
        let map_fd = map.as_fd().as_raw_fd();
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

        let mut resume_at = [0u8; 4];
        let mut next = [0u8; 4];
        let mut first = true;

        loop {
            let mut attr = BatchAttr {
                in_batch: if first { 0 } else { resume_at.as_mut_ptr() as u64 },
                out_batch: next.as_mut_ptr() as u64,
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
            let error = (ret != 0).then(io::Error::last_os_error);

            if error.as_ref().and_then(io::Error::raw_os_error) == Some(libc::ENOSPC) {
                let grown = self.keys_buf.len() * 2;
                self.keys_buf.resize(grown, [0u8; 4]);
                self.values_buf
                    .resize(grown, [0u8; size_of::<RawProcessStats>()]);
                continue;
            }

            for value in &self.values_buf[..attr.count as usize] {
                self.out_buf.push(unsafe {
                    std::ptr::read_unaligned(value.as_ptr() as *const RawProcessStats)
                });
            }

            match error {
                None => {
                    resume_at = next;
                    first = false;
                }
                Some(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
                Some(e) => return Err(e.into()),
            }
        }

        Ok(&self.out_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libbpf_rs::{MapFlags, MapHandle, MapType, libbpf_sys};

    #[test]
    #[ignore = "creates a BPF map: needs root"]
    fn a_map_larger_than_one_chunk_reads_out_whole() {
        const ENTRIES: u32 = 3 * CHUNK as u32 + 17;
        let opts = libbpf_sys::bpf_map_create_opts {
            sz: size_of::<libbpf_sys::bpf_map_create_opts>() as _,
            map_flags: libbpf_sys::BPF_F_NO_PREALLOC,
            ..Default::default()
        };
        let map = MapHandle::create(
            MapType::Hash,
            Some("batch_test"),
            4,
            size_of::<RawProcessStats>() as u32,
            ENTRIES,
            &opts,
        )
        .unwrap();
        for pid in 1..=ENTRIES {
            let mut value = [0u8; size_of::<RawProcessStats>()];
            value[..4].copy_from_slice(&pid.to_ne_bytes());
            map.update(&pid.to_ne_bytes(), &value, MapFlags::NO_EXIST).unwrap();
        }

        let mut batch = BatchLookup::new();
        let mut pids: Vec<u32> = batch
            .lookup(&map)
            .unwrap()
            .iter()
            .map(|s| s.global_pid)
            .collect();
        pids.sort_unstable();
        assert_eq!(pids, (1..=ENTRIES).collect::<Vec<_>>());
    }
}
