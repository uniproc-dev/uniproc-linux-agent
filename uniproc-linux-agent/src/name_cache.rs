use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::hash_map::Iter;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::io::{FromRawFd, RawFd};

const BPF_LINK_CREATE: i64 = 28;
const BPF_ITER_CREATE: i64 = 33;
const BPF_TRACE_ITER: u32 = 28;

// [tgid: 4][start_time: 8][path: 64] = 76
const RECORD_SIZE: usize = 4 + 8 + 64;

pub struct CacheEntry {
    pub name: [u8; 64],
    pub start_time: u64,
}

pub struct NameCache {
    cache: FxHashMap<u32, CacheEntry>,
    iter_prog_fd: RawFd,
    read_buf: Vec<u8>,
}

impl NameCache {
    pub fn new(iter_prog_fd: RawFd) -> Self {
        Self {
            cache: FxHashMap::default(),
            iter_prog_fd,
            read_buf: Vec::with_capacity(4096),
        }
    }

    pub fn get_names(&self) -> Iter<'_, u32, CacheEntry> {
        self.cache.iter()
    }

    pub fn refresh(&mut self, live_pids: &FxHashSet<u32>) -> anyhow::Result<()> {
        self.cache.retain(|pid, _| live_pids.contains(pid));

        self.fill_from_iter()
    }

    pub fn get(&self, pid: u32) -> Option<&[u8; 64]> {
        self.cache.get(&pid).map(|e| &e.name)
    }

    pub fn get_str(&self, pid: u32) -> &str {
        self.cache
            .get(&pid)
            .map(|e| {
                let end = e.name.iter().position(|&b| b == 0).unwrap_or(64);
                std::str::from_utf8(&e.name[..end]).unwrap_or("?")
            })
            .unwrap_or("?")
    }

    fn fill_from_iter(&mut self) -> anyhow::Result<()> {
        let link_fd = bpf_link_create(self.iter_prog_fd)?;
        let iter_fd = bpf_iter_create(link_fd)?;
        unsafe { libc::close(link_fd) };

        let mut file = unsafe { File::from_raw_fd(iter_fd) };

        self.read_buf.clear();
        let mut tmp = [0u8; 4096];
        loop {
            let n = file.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }

        for chunk in self.read_buf.chunks_exact(RECORD_SIZE) {
            let tgid = u32::from_ne_bytes(chunk[..4].try_into()?);
            let start_time = u64::from_ne_bytes(chunk[4..12].try_into()?);
            let path = &chunk[12..76];

            if let Some(entry) = self.cache.get(&tgid) {
                if entry.start_time == start_time {
                    continue;
                }
            }

            let name = parse_name(path);
            self.cache.insert(tgid, CacheEntry { name, start_time });
        }

        Ok(())
    }
}

fn parse_name(path: &[u8]) -> [u8; 64] {
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    let slice = &path[..end];
    let name = match slice.iter().rposition(|&b| b == b'/') {
        Some(pos) => &slice[pos + 1..],
        None => slice,
    };

    let mut out = [0u8; 64];
    let len = name.len().min(63);
    out[..len].copy_from_slice(&name[..len]);
    out
}

fn bpf_link_create(prog_fd: RawFd) -> anyhow::Result<RawFd> {
    #[repr(C, align(8))]
    struct Attr {
        prog_fd: u32,
        target_fd: u32,
        attach_type: u32,
        flags: u32,
        _pad: [u8; 112],
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_LINK_CREATE,
            &Attr {
                prog_fd: prog_fd as u32,
                target_fd: 0,
                attach_type: BPF_TRACE_ITER,
                flags: 0,
                _pad: [0; 112],
            } as *const _ as *const libc::c_void,
            std::mem::size_of::<Attr>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ret as RawFd)
    }
}

fn bpf_iter_create(link_fd: RawFd) -> anyhow::Result<RawFd> {
    #[repr(C, align(8))]
    struct Attr {
        link_fd: u32,
        flags: u32,
        _pad: [u8; 120],
    }

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_ITER_CREATE,
            &Attr {
                link_fd: link_fd as u32,
                flags: 0,
                _pad: [0; 120],
            } as *const _ as *const libc::c_void,
            std::mem::size_of::<Attr>() as u32,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ret as RawFd)
    }
}
