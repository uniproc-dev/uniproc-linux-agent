use std::io::Read;
use std::mem::size_of;

use libbpf_rs::{Iter, Link};
use rustc_hash::FxHashMap;

const RECORD_THREAD: u32 = 1;
const RECORD_PROCESS: u32 = 2;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct Counters {
    pub utime: u64,
    pub stime: u64,
    pub runtime: u64,
    pub nvcsw: u64,
    pub nivcsw: u64,
    pub min_flt: u64,
    pub maj_flt: u64,
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

impl Counters {
    fn add(&mut self, other: &Counters) {
        self.utime += other.utime;
        self.stime += other.stime;
        self.runtime += other.runtime;
        self.nvcsw += other.nvcsw;
        self.nivcsw += other.nivcsw;
        self.min_flt += other.min_flt;
        self.maj_flt += other.maj_flt;
        self.rchar += other.rchar;
        self.wchar += other.wchar;
        self.syscr += other.syscr;
        self.syscw += other.syscw;
        self.read_bytes += other.read_bytes;
        self.write_bytes += other.write_bytes;
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ThreadRecord {
    kind: u32,
    tgid: u32,
    counters: Counters,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcessRecord {
    kind: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub local_pid: u32,
    pub start_boottime: u64,
    pub exec_id: u64,
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub exited: Counters,
    pub rss_file: u64,
    pub rss_anon: u64,
    pub rss_shmem: u64,
    pub swap: u64,
    pub hiwater_rss: u64,
    pub total_vm: u64,
    pub hiwater_vm: u64,
    pub threads: u32,
    pub state: u32,
    pub exit_state: u32,
    pub static_prio: i32,
    pub policy: u32,
    pub rt_priority: u32,
    pub uid: u32,
    pub view_pid: u32,
    pub comm: [u8; 16],
}

impl ProcessRecord {
    pub fn comm(&self) -> String {
        let end = self.comm.iter().position(|&b| b == 0).unwrap_or(self.comm.len());
        String::from_utf8_lossy(&self.comm[..end]).into_owned()
    }
}

/// A process as the kernel holds it, its counters summed over live and exited threads.
#[derive(Debug, Clone, Copy)]
pub struct Task {
    pub process: ProcessRecord,
    pub counters: Counters,
}

/// Walks every task with the task_snapshot iterator.
pub struct TaskReader {
    buf: Vec<u8>,
}

impl TaskReader {
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(64 * 1024),
        }
    }

    pub fn read(&mut self, link: &Link) -> anyhow::Result<Vec<Task>> {
        self.buf.clear();
        Iter::new(link)?.read_to_end(&mut self.buf)?;
        parse(&self.buf)
    }
}

fn parse(mut bytes: &[u8]) -> anyhow::Result<Vec<Task>> {
    let mut order = Vec::new();
    let mut tasks: FxHashMap<u32, Task> = FxHashMap::default();
    let mut orphans: Vec<(u32, Counters)> = Vec::new();

    while bytes.len() >= 4 {
        let kind = u32::from_ne_bytes(bytes[..4].try_into()?);
        match kind {
            RECORD_PROCESS => {
                let record: ProcessRecord = take(&mut bytes)?;
                order.push(record.tgid);
                tasks.insert(
                    record.tgid,
                    Task {
                        process: record,
                        counters: record.exited,
                    },
                );
            }
            RECORD_THREAD => {
                let record: ThreadRecord = take(&mut bytes)?;
                match tasks.get_mut(&record.tgid) {
                    Some(task) => task.counters.add(&record.counters),
                    None => orphans.push((record.tgid, record.counters)),
                }
            }
            other => anyhow::bail!("task_snapshot record of unknown kind {other}"),
        }
    }

    for (tgid, counters) in orphans {
        if let Some(task) = tasks.get_mut(&tgid) {
            task.counters.add(&counters);
        }
    }

    Ok(order.into_iter().filter_map(|tgid| tasks.remove(&tgid)).collect())
}

fn take<T: Copy>(bytes: &mut &[u8]) -> anyhow::Result<T> {
    let size = size_of::<T>();
    if bytes.len() < size {
        anyhow::bail!("task_snapshot record cut short: {} of {size} bytes", bytes.len());
    }
    let value = unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) };
    *bytes = &bytes[size..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_of<T: Copy>(value: &T) -> Vec<u8> {
        let ptr = value as *const T as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, size_of::<T>()) }.to_vec()
    }

    fn process(tgid: u32, exited_utime: u64) -> ProcessRecord {
        ProcessRecord {
            kind: RECORD_PROCESS,
            tgid,
            ppid: 1,
            local_pid: tgid,
            start_boottime: 1_000 + tgid as u64,
            exec_id: 0,
            mnt_ns: 0,
            pid_ns: 0,
            exited: Counters {
                utime: exited_utime,
                ..Default::default()
            },
            rss_file: 0,
            rss_anon: 0,
            rss_shmem: 0,
            swap: 0,
            hiwater_rss: 0,
            total_vm: 0,
            hiwater_vm: 0,
            threads: 2,
            state: 0,
            exit_state: 0,
            static_prio: 120,
            policy: 0,
            rt_priority: 0,
            uid: 0,
            view_pid: tgid,
            comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    fn thread(tgid: u32, utime: u64) -> ThreadRecord {
        ThreadRecord {
            kind: RECORD_THREAD,
            tgid,
            counters: Counters {
                utime,
                ..Default::default()
            },
        }
    }

    #[test]
    fn a_process_sums_its_live_and_exited_threads() {
        let mut stream = bytes_of(&process(7, 100));
        stream.extend(bytes_of(&thread(7, 10)));
        stream.extend(bytes_of(&thread(7, 5)));
        stream.extend(bytes_of(&process(8, 0)));
        stream.extend(bytes_of(&thread(8, 1)));

        let tasks = parse(&stream).unwrap();
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].process.tgid, 7);
        assert_eq!(tasks[0].counters.utime, 115);
        assert_eq!(tasks[0].process.comm(), "bash");
        assert_eq!(tasks[1].counters.utime, 1);
    }

    #[test]
    fn a_thread_seen_before_its_leader_still_counts() {
        let mut stream = bytes_of(&thread(9, 3));
        stream.extend(bytes_of(&process(9, 0)));
        let tasks = parse(&stream).unwrap();
        assert_eq!(tasks[0].counters.utime, 3);
    }

    #[test]
    fn a_record_cut_short_is_an_error() {
        let stream = bytes_of(&process(7, 0));
        assert!(parse(&stream[..stream.len() - 1]).is_err());
    }

    #[test]
    fn the_records_match_the_c_layout() {
        assert_eq!(size_of::<ThreadRecord>(), 8 + 13 * 8);
        assert_eq!(size_of::<ProcessRecord>(), 16 + 4 * 8 + 13 * 8 + 7 * 8 + 8 * 4 + 16);
    }
}
