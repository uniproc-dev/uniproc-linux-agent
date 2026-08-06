use crate::name_cache::NameCache;
use libbpf_rs::{MapCore, MapMut};
use rustc_hash::FxHashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::io::{FromRawFd, RawFd};

const BPF_LINK_CREATE: i64 = 28;
const BPF_ITER_CREATE: i64 = 33;
const BPF_MAP_DELETE_BATCH: i64 = 27;
const BPF_TRACE_ITER: u32 = 28;

const EMA_ALPHA: f32 = 0.2;

pub struct IterGc {
    tick: u32,
    every_n_ticks: u32,
    iter_prog_fd: RawFd,
    stale_buf: Vec<[u8; 4]>,
    live_pids_buf: FxHashSet<u32>,
    stale_ema: f32,
}

impl IterGc {
    pub fn new(every_n_ticks: u32, iter_prog_fd: RawFd) -> Self {
        Self {
            tick: 0,
            every_n_ticks,
            iter_prog_fd,
            stale_buf: Vec::with_capacity(128),
            live_pids_buf: FxHashSet::default(),
            stale_ema: 0.0,
        }
    }

    pub fn live_pids(&mut self) -> &FxHashSet<u32> {
        &self.live_pids_buf
    }

    pub fn maybe_gc(&mut self, map: &mut MapMut) -> anyhow::Result<()> {
        self.tick += 1;
        if self.tick % self.every_n_ticks != 0 {
            return Ok(());
        }

        self.live_pids_buf.clear();
        fill_iter_pids(self.iter_prog_fd, &mut self.live_pids_buf)?;

        self.stale_buf.clear();
        for k in map.keys() {
            let Ok(arr): Result<[u8; 4], _> = k.try_into() else {
                continue;
            };
            if !self.live_pids_buf.contains(&u32::from_ne_bytes(arr)) {
                self.stale_buf.push(arr);
            }
        }

        let current = self.stale_buf.len() as f32;
        self.stale_ema = (self.stale_ema * (1.0 - EMA_ALPHA) + current * EMA_ALPHA).max(current);

        let target_cap = ((self.stale_ema * 1.25) as usize);
        if self.stale_buf.capacity() > target_cap * 2 {
            self.stale_buf.shrink_to(target_cap);
        }

        #[cfg(debug_assertions)]
        self.debug_report();

        if self.stale_buf.is_empty() {
            return Ok(());
        }

        batch_delete(map.as_fd().as_raw_fd(), &self.stale_buf)
    }

    #[cfg(debug_assertions)]
    fn debug_report(&self) {
        let mut proc_pids = FxHashSet::default();
        fill_proc_pids(&mut proc_pids);

        let in_iter_not_proc: Vec<u32> =
            self.live_pids_buf.difference(&proc_pids).copied().collect();
        let in_proc_not_iter: Vec<u32> =
            proc_pids.difference(&self.live_pids_buf).copied().collect();

        if !in_iter_not_proc.is_empty() {
            eprintln!(
                "DBG: iter has but /proc missing ({}): {:?}",
                in_iter_not_proc.len(),
                &in_iter_not_proc[..in_iter_not_proc.len().min(10)]
            );
        }
        if !in_proc_not_iter.is_empty() {
            eprintln!(
                "DBG: /proc has but iter missing ({}): {:?}",
                in_proc_not_iter.len(),
                &in_proc_not_iter[..in_proc_not_iter.len().min(10)]
            );
        }
        if !self.stale_buf.is_empty() {
            let pids: Vec<u32> = self
                .stale_buf
                .iter()
                .map(|k| u32::from_ne_bytes(*k))
                .collect();
            eprintln!(
                "DBG: stale in BPF map ({}): {:?}",
                pids.len(),
                &pids[..pids.len().min(10)]
            );
        }
    }
}

fn fill_iter_pids(iter_prog_fd: RawFd, out: &mut FxHashSet<u32>) -> anyhow::Result<()> {
    let link_fd = bpf_link_create(iter_prog_fd)?;
    let iter_fd = bpf_iter_create(link_fd)?;
    unsafe { libc::close(link_fd) };

    let mut file = unsafe { File::from_raw_fd(iter_fd) };
    let mut buf = [0u8; 4096];
    loop {
        let n = io::Read::read(&mut file, &mut buf)?;
        if n == 0 {
            break;
        }

        for chunk in buf[..n].chunks_exact(4) {
            out.insert(u32::from_ne_bytes(chunk.try_into()?));
        }
    }
    Ok(())
}

#[cfg(debug_assertions)]
fn fill_proc_pids(out: &mut FxHashSet<u32>) {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
            out.insert(pid);
        }
    }
}

fn batch_delete(map_fd: RawFd, keys: &[[u8; 4]]) -> anyhow::Result<()> {
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

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_DELETE_BATCH,
            &BatchAttr {
                in_batch: 0,
                out_batch: 0,
                keys: keys.as_ptr() as u64,
                values: 0,
                count: keys.len() as u32,
                map_fd: map_fd as u32,
                elem_flags: 0,
                flags: 0,
                _pad: [0; 64],
            } as *const _ as *const libc::c_void,
            std::mem::size_of::<BatchAttr>() as u32,
        )
    };

    if ret < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOENT) {
            return Err(e.into());
        }
    }
    Ok(())
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
