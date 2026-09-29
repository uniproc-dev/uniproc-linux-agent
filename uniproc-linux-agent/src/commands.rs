use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::procfs;

fn errno() -> u32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO) as u32
}

/// Whether a start time in ns lands on the tick /proc/<pid>/stat reports.
fn same_start(sequence_number: u64, start_ticks: u64, user_hz: u64) -> bool {
    sequence_number / (1_000_000_000 / user_hz) == start_ticks
}

/// A pidfd for `pid`, once it is known to be the process `sequence_number` names.
fn open(pid: u32, sequence_number: u64) -> Result<OwnedFd, u32> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(errno());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
    if sequence_number != 0 {
        match procfs::start_ticks(pid) {
            Some(ticks) if same_start(sequence_number, ticks, procfs::user_hz()) => {}
            _ => return Err(libc::ESRCH as u32),
        }
    }
    Ok(fd)
}

pub fn signal(pid: u32, sequence_number: u64, signal: u32) -> u32 {
    let fd = match open(pid, sequence_number) {
        Ok(fd) => fd,
        Err(code) => return code,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0u32,
        )
    };
    if ret < 0 { errno() } else { 0 }
}

fn threads(pid: u32) -> Result<Vec<libc::pid_t>, u32> {
    let entries = fs::read_dir(format!("/proc/{pid}/task")).map_err(|_| libc::ESRCH as u32)?;
    Ok(entries
        .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect())
}

fn each_thread(pid: u32, sequence_number: u64, apply: impl Fn(libc::pid_t) -> libc::c_int) -> u32 {
    let _fd = match open(pid, sequence_number) {
        Ok(fd) => fd,
        Err(code) => return code,
    };
    let tids = match threads(pid) {
        Ok(tids) => tids,
        Err(code) => return code,
    };
    let mut first_error = 0;
    for tid in tids {
        if apply(tid) < 0 {
            let code = errno();
            if code != libc::ESRCH as u32 && first_error == 0 {
                first_error = code;
            }
        }
    }
    first_error
}

pub fn set_nice(pid: u32, sequence_number: u64, nice: i32) -> u32 {
    if !(-20..=19).contains(&nice) {
        return libc::EINVAL as u32;
    }
    each_thread(pid, sequence_number, |tid| unsafe {
        libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, nice)
    })
}

pub fn set_affinity(pid: u32, sequence_number: u64, mask: &[u64]) -> u32 {
    if mask.iter().all(|&word| word == 0) {
        return libc::EINVAL as u32;
    }
    each_thread(pid, sequence_number, |tid| unsafe {
        libc::syscall(
            libc::SYS_sched_setaffinity,
            tid,
            std::mem::size_of_val(mask),
            mask.as_ptr(),
        ) as libc::c_int
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_time_matches_its_own_tick_only() {
        assert!(same_start(12_345_678_901, 1234, 100));
        assert!(!same_start(12_345_678_901, 1235, 100));
        assert!(same_start(0, 0, 100));
    }

    #[test]
    fn the_agent_itself_is_found_and_a_wrong_start_is_refused() {
        let pid = std::process::id();
        let ticks = procfs::start_ticks(pid).unwrap();
        let ns = ticks * (1_000_000_000 / procfs::user_hz());
        assert!(open(pid, ns).is_ok());
        assert!(open(pid, 0).is_ok());
        assert_eq!(open(pid, ns + 10_000_000_000).err(), Some(libc::ESRCH as u32));
    }

    #[test]
    fn signal_zero_reaches_the_agent_itself() {
        assert_eq!(signal(std::process::id(), 0, 0), 0);
    }

    #[test]
    fn a_nice_out_of_range_is_refused() {
        assert_eq!(set_nice(std::process::id(), 0, 20), libc::EINVAL as u32);
        assert_eq!(set_affinity(std::process::id(), 0, &[0]), libc::EINVAL as u32);
    }

    #[test]
    fn a_pid_that_does_not_exist_is_esrch() {
        assert_eq!(signal(0x3fff_fff0, 0, 0), libc::ESRCH as u32);
    }
}
