use std::io;
use std::os::fd::RawFd;

use crate::iter_gc::open_iter;

pub fn seed_existing_processes(prog_fd: RawFd) -> anyhow::Result<()> {
    io::copy(&mut open_iter(prog_fd)?, &mut io::sink())?;
    Ok(())
}
