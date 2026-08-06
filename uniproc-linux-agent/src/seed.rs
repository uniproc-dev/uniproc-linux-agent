use std::fs::File;
use std::io::{self, Read};
use std::os::unix::io::{FromRawFd, RawFd};

const BPF_LINK_CREATE: i64 = 28;
const BPF_ITER_CREATE: i64 = 33;
const BPF_TRACE_ITER: u32 = 28;

pub fn seed_existing_processes(prog_fd: RawFd) -> anyhow::Result<()> {
    let link_fd = bpf_link_create(prog_fd)?;
    let iter_fd = bpf_iter_create(link_fd)?;
    unsafe { libc::close(link_fd) };

    let mut iter_file = unsafe { File::from_raw_fd(iter_fd) };

    let mut buf = [0u8; 4096];
    loop {
        match iter_file.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

pub(crate) fn bpf_link_create(prog_fd: RawFd) -> anyhow::Result<RawFd> {
    #[repr(C, align(8))]
    struct BpfLinkCreateAttr {
        prog_fd: u32,
        target_fd: u32,
        attach_type: u32,
        flags: u32,
        _pad: [u8; 112],
    }

    let attr = BpfLinkCreateAttr {
        prog_fd: prog_fd as u32,
        target_fd: 0,
        attach_type: BPF_TRACE_ITER,
        flags: 0,
        _pad: [0; 112],
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_LINK_CREATE,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfLinkCreateAttr>() as u32,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ret as RawFd)
    }
}

pub(crate) fn bpf_iter_create(link_fd: RawFd) -> anyhow::Result<RawFd> {
    #[repr(C, align(8))]
    struct BpfIterCreateAttr {
        link_fd: u32,
        flags: u32,
        _pad: [u8; 120],
    }

    let attr = BpfIterCreateAttr {
        link_fd: link_fd as u32,
        flags: 0,
        _pad: [0; 120],
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_ITER_CREATE,
            &attr as *const _ as *const libc::c_void,
            std::mem::size_of::<BpfIterCreateAttr>() as u32,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(ret as RawFd)
    }
}
