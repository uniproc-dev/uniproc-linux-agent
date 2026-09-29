use std::fs;
use std::path::Path;
use std::time::SystemTime;

use rustc_hash::FxHashMap;

use crate::model::{
    CpuTimes, MachineCpu, MachineDisk, MachineLoad, MachineMemory, NetworkAdapter,
};

pub fn cmdline(pid: u32) -> Vec<String> {
    let Ok(raw) = fs::read(format!("/proc/{pid}/cmdline")) else {
        return Vec::new();
    };
    split_cmdline(&raw)
}

fn split_cmdline(raw: &[u8]) -> Vec<String> {
    let raw = raw.strip_suffix(&[0]).unwrap_or(raw);
    if raw.is_empty() {
        return Vec::new();
    }
    raw.split(|&b| b == 0)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect()
}

pub fn exe_path(pid: u32) -> String {
    fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn cgroup(pid: u32) -> String {
    fs::read_to_string(format!("/proc/{pid}/cgroup"))
        .map(|content| unified_cgroup(&content))
        .unwrap_or_default()
}

fn unified_cgroup(content: &str) -> String {
    content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .unwrap_or_default()
        .to_string()
}

/// Names for uids, from the agent's own /etc/passwd, reread when it changes.
#[derive(Default)]
pub struct Users {
    names: FxHashMap<u32, String>,
    modified: Option<SystemTime>,
}

impl Users {
    pub fn refresh(&mut self) {
        let modified = fs::metadata("/etc/passwd").and_then(|m| m.modified()).ok();
        if modified.is_some() && modified == self.modified {
            return;
        }
        self.modified = modified;
        self.names = fs::read_to_string("/etc/passwd")
            .map(|content| parse_passwd(&content))
            .unwrap_or_default();
    }

    pub fn name(&self, uid: u32) -> String {
        self.names.get(&uid).cloned().unwrap_or_default()
    }
}

fn parse_passwd(content: &str) -> FxHashMap<u32, String> {
    content
        .lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?;
            let uid = fields.nth(1)?.parse().ok()?;
            Some((uid, name.to_string()))
        })
        .collect()
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(clock, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

pub fn boottime_ns() -> u64 {
    clock_ns(libc::CLOCK_BOOTTIME)
}

/// Wall-clock ns since the epoch at boottime 0.
pub fn boot_epoch_ns() -> u64 {
    clock_ns(libc::CLOCK_REALTIME).saturating_sub(clock_ns(libc::CLOCK_BOOTTIME))
}

pub fn user_hz() -> u64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as u64 } else { 100 }
}

pub fn page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size > 0 { size as u64 } else { 4096 }
}

/// The start time /proc/<pid>/stat reports, in USER_HZ ticks since boot.
pub fn start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_start_ticks(&stat)
}

fn stat_start_ticks(stat: &str) -> Option<u64> {
    let after_comm = &stat[stat.rfind(')')? + 1..];
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

pub struct Cpu {
    pub machine: MachineCpu,
    pub processors: Vec<CpuTimes>,
}

pub fn cpu(user_hz: u64) -> Option<Cpu> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let mut cpu = parse_stat(&stat, user_hz)?;
    cpu.machine.current_mhz = fs::read_to_string("/proc/cpuinfo")
        .map(|content| fastest_mhz(&content))
        .unwrap_or(0);
    Some(cpu)
}

fn parse_stat(stat: &str, user_hz: u64) -> Option<Cpu> {
    let to_100ns = |ticks: u64| ticks * (10_000_000 / user_hz);
    let mut total = None;
    let mut processors = Vec::new();
    for line in stat.lines() {
        let mut fields = line.split_whitespace();
        let Some(label) = fields.next() else { continue };
        if !label.starts_with("cpu") {
            continue;
        }
        let v: Vec<u64> = fields.map(|f| f.parse().unwrap_or(0)).collect();
        let at = |i: usize| v.get(i).copied().map(to_100ns).unwrap_or(0);
        let times = CpuTimes {
            user: at(0),
            nice: at(1),
            system: at(2),
            idle: at(3),
            iowait: at(4),
            irq: at(5),
            softirq: at(6),
            steal: at(7),
            guest: at(8),
            guest_nice: at(9),
        };
        if label == "cpu" {
            total = Some(times);
        } else {
            processors.push(times);
        }
    }
    Some(Cpu {
        machine: MachineCpu {
            times: total?,
            count: processors.len() as u32,
            current_mhz: 0,
        },
        processors,
    })
}

fn fastest_mhz(cpuinfo: &str) -> u32 {
    cpuinfo
        .lines()
        .filter(|line| line.starts_with("cpu MHz"))
        .filter_map(|line| line.split(':').nth(1)?.trim().parse::<f64>().ok())
        .fold(0.0, f64::max) as u32
}

pub fn memory() -> Option<MachineMemory> {
    parse_meminfo(&fs::read_to_string("/proc/meminfo").ok()?)
}

fn parse_meminfo(content: &str) -> Option<MachineMemory> {
    let mut kb: FxHashMap<&str, u64> = FxHashMap::default();
    for line in content.lines() {
        let Some((key, rest)) = line.split_once(':') else { continue };
        if let Some(value) = rest.split_whitespace().next().and_then(|v| v.parse().ok()) {
            kb.insert(key, value);
        }
    }
    let get = |key: &str| kb.get(key).map(|v| v * 1024).unwrap_or(0);
    kb.get("MemTotal")?;
    Some(MachineMemory {
        total: get("MemTotal"),
        free: get("MemFree"),
        available: get("MemAvailable"),
        buffers: get("Buffers"),
        cached: get("Cached"),
        shmem: get("Shmem"),
        swap_total: get("SwapTotal"),
        swap_free: get("SwapFree"),
        commit_limit: get("CommitLimit"),
        committed: get("Committed_AS"),
    })
}

pub fn disk() -> Option<MachineDisk> {
    let whole: Vec<String> = fs::read_dir("/sys/block")
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with("loop") && !name.starts_with("ram"))
        .collect();
    Some(parse_diskstats(&fs::read_to_string("/proc/diskstats").ok()?, &whole))
}

fn parse_diskstats(content: &str, whole: &[String]) -> MachineDisk {
    let mut disk = MachineDisk::default();
    for line in content.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 13 || !whole.iter().any(|name| name == f[2]) {
            continue;
        }
        let at = |i: usize| f[i].parse::<u64>().unwrap_or(0);
        disk.read_ops += at(3);
        disk.read_bytes += at(5) * 512;
        disk.write_ops += at(7);
        disk.write_bytes += at(9) * 512;
        disk.busy_time += at(12) * 10_000;
    }
    disk
}

pub fn adapters() -> Vec<NetworkAdapter> {
    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return Vec::new();
    };
    parse_net_dev(&content)
        .into_iter()
        .filter(|a| a.name != "lo")
        .map(|mut a| {
            let dir = Path::new("/sys/class/net").join(&a.name);
            a.hardware = dir.join("device").exists();
            a.up = fs::read_to_string(dir.join("operstate"))
                .map(|s| s.trim() == "up")
                .unwrap_or(false);
            a.link_speed = fs::read_to_string(dir.join("speed"))
                .ok()
                .and_then(|s| s.trim().parse::<i64>().ok())
                .filter(|&mbps| mbps > 0)
                .map(|mbps| mbps as u64 * 1_000_000)
                .unwrap_or(0);
            a
        })
        .collect()
}

fn parse_net_dev(content: &str) -> Vec<NetworkAdapter> {
    content
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let v: Vec<u64> = rest.split_whitespace().map(|f| f.parse().unwrap_or(0)).collect();
            if v.len() < 10 {
                return None;
            }
            Some(NetworkAdapter {
                name: name.trim().to_string(),
                hardware: false,
                link_speed: 0,
                up: false,
                rx_bytes: v[0],
                rx_packets: v[1],
                tx_bytes: v[8],
                tx_packets: v[9],
            })
        })
        .collect()
}

pub fn load() -> Option<MachineLoad> {
    parse_loadavg(&fs::read_to_string("/proc/loadavg").ok()?)
}

fn parse_loadavg(content: &str) -> Option<MachineLoad> {
    let mut f = content.split_whitespace();
    let centi = |s: &str| s.parse::<f64>().ok().map(|v| (v * 100.0).round() as u32);
    let load1 = centi(f.next()?)?;
    let load5 = centi(f.next()?)?;
    let load15 = centi(f.next()?)?;
    let (running, tasks) = f.next()?.split_once('/')?;
    Some(MachineLoad {
        load1,
        load5,
        load15,
        running: running.parse().ok()?,
        tasks: tasks.parse().ok()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cmdline_splits_on_nul_and_drops_the_last_one() {
        assert_eq!(split_cmdline(b"bash\0-l\0"), vec!["bash", "-l"]);
        assert_eq!(split_cmdline(b""), Vec::<String>::new());
        assert_eq!(split_cmdline(b"a b\0"), vec!["a b"]);
    }

    #[test]
    fn the_unified_cgroup_line_is_taken() {
        assert_eq!(
            unified_cgroup("1:name=systemd:/x\n0::/user.slice/session-1.scope\n"),
            "/user.slice/session-1.scope"
        );
    }

    #[test]
    fn passwd_maps_uids_to_names() {
        let users = parse_passwd("root:x:0:0:root:/root:/bin/bash\nignat:x:1000:1000::/home/ignat:/bin/bash\n");
        assert_eq!(users[&0], "root");
        assert_eq!(users[&1000], "ignat");
    }

    #[test]
    fn the_start_time_survives_a_comm_with_spaces_and_parens() {
        let stat = "42 (a b) c) S 1 42 42 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 12345 1000 50";
        assert_eq!(stat_start_ticks(stat), Some(12345));
    }

    #[test]
    fn proc_stat_is_split_into_the_total_and_each_cpu() {
        let stat = "cpu  10 1 5 100 2 0 1 0 3 0\ncpu0 6 1 3 50 1 0 1 0 3 0\ncpu1 4 0 2 50 1 0 0 0 0 0\nintr 1\n";
        let cpu = parse_stat(stat, 100).unwrap();
        assert_eq!(cpu.machine.count, 2);
        assert_eq!(cpu.machine.times.user, 10 * 100_000);
        assert_eq!(cpu.machine.times.guest, 3 * 100_000);
        assert_eq!(cpu.processors[1].idle, 50 * 100_000);
    }

    #[test]
    fn meminfo_is_in_bytes() {
        let m = parse_meminfo("MemTotal: 1000 kB\nMemAvailable: 400 kB\nCommitted_AS: 7 kB\n").unwrap();
        assert_eq!(m.total, 1_024_000);
        assert_eq!(m.available, 409_600);
        assert_eq!(m.committed, 7 * 1024);
        assert_eq!(m.free, 0);
    }

    #[test]
    fn diskstats_counts_whole_disks_only() {
        let stats = "   8       0 sda 10 0 80 0 20 0 160 0 0 7 0\n   8       1 sda1 9 0 72 0 19 0 150 0 0 6 0\n";
        let disk = parse_diskstats(stats, &["sda".to_string()]);
        assert_eq!(disk.read_ops, 10);
        assert_eq!(disk.read_bytes, 80 * 512);
        assert_eq!(disk.write_bytes, 160 * 512);
        assert_eq!(disk.busy_time, 7 * 10_000);
    }

    #[test]
    fn net_dev_rows_are_parsed() {
        let dev = "Inter-|   Receive\n face |bytes\n  eth0: 100 2 0 0 0 0 0 0 200 3 0 0 0 0 0 0\n    lo: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n";
        let adapters = parse_net_dev(dev);
        assert_eq!(adapters[0].name, "eth0");
        assert_eq!(adapters[0].rx_bytes, 100);
        assert_eq!(adapters[0].tx_packets, 3);
    }

    #[test]
    fn loadavg_is_in_hundredths() {
        let load = parse_loadavg("0.52 1.00 0.07 2/345 6789\n").unwrap();
        assert_eq!((load.load1, load.load5, load.load15), (52, 100, 7));
        assert_eq!((load.running, load.tasks), (2, 345));
    }
}
