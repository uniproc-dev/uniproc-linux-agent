use std::collections::BTreeMap;
use std::sync::Arc;

use uniproc_agent_kit::Tagged;

use crate::report::{LinuxDockerContainerInfo, LinuxEnvironmentInfo};

/// A process: its pid and its start time, which together never repeat within a boot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key {
    pub pid: u32,
    pub sequence_number: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Passport {
    pub key: Key,
    /// The pid in the agent's own pid namespace; 0 when the process is outside it.
    pub view_pid: u32,
    pub parent_pid: u32,
    pub start_time: u64,
    pub name: String,
    pub exe_path: String,
    pub cmdline: Vec<String>,
    pub uid: u32,
    pub user: String,
    pub local_pid: u32,
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub cgroup: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Unknown,
    Running,
    Sleeping,
    DiskSleep,
    Stopped,
    TracingStop,
    Zombie,
    Idle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedPolicy {
    Unknown,
    Other,
    Fifo,
    Rr,
    Batch,
    Idle,
    Deadline,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct State {
    pub key: Key,
    pub state: TaskState,
    pub nice: i32,
    pub policy: SchedPolicy,
    pub rt_priority: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Transports {
    pub tcp_loopback_rx: u64,
    pub tcp_loopback_tx: u64,
    pub tcp_remote_rx: u64,
    pub tcp_remote_tx: u64,
    pub udp_loopback_rx: u64,
    pub udp_loopback_tx: u64,
    pub udp_remote_rx: u64,
    pub udp_remote_tx: u64,
    pub unix_rx: u64,
    pub unix_tx: u64,
    pub vsock_rx: u64,
    pub vsock_tx: u64,
    pub p9_rx: u64,
    pub p9_tx: u64,
}

impl Transports {
    pub fn net_rx(&self) -> u64 {
        self.tcp_loopback_rx + self.tcp_remote_rx + self.udp_loopback_rx + self.udp_remote_rx
    }

    pub fn net_tx(&self) -> u64 {
        self.tcp_loopback_tx + self.tcp_remote_tx + self.udp_loopback_tx + self.udp_remote_tx
    }
}

/// What the agent's own probes counted for a process.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Probed {
    pub file_read_ops: u64,
    pub file_write_ops: u64,
    pub file_read_bytes: u64,
    pub file_write_bytes: u64,
    pub pipe_read_bytes: u64,
    pub pipe_write_bytes: u64,
    pub sendfile_bytes: u64,
    pub transports: Transports,
}

/// One process's metrics; times in 100 ns, sizes in bytes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Row {
    pub key: Key,
    pub cpu_user_time: u64,
    pub cpu_kernel_time: u64,
    pub cpu_run_time: u64,
    pub resident_set: u64,
    pub resident_anon: u64,
    pub resident_file: u64,
    pub resident_shmem: u64,
    pub peak_resident_set: u64,
    pub virtual_size: u64,
    pub peak_virtual_size: u64,
    pub swap: u64,
    pub minor_faults: u64,
    pub major_faults: u64,
    pub threads: u32,
    pub voluntary_context_switches: u64,
    pub involuntary_context_switches: u64,
    pub io_read_ops: u64,
    pub io_write_ops: u64,
    pub io_read_bytes: u64,
    pub io_write_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
    pub probed: Option<Probed>,
}

/// Cumulative, 100 ns.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
    pub guest: u64,
    pub guest_nice: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MachineCpu {
    pub times: CpuTimes,
    pub count: u32,
    pub current_mhz: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MachineMemory {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub shmem: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub commit_limit: u64,
    pub committed: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MachineDisk {
    pub read_ops: u64,
    pub write_ops: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub busy_time: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NetworkAdapter {
    pub name: String,
    pub hardware: bool,
    pub link_speed: u64,
    pub up: bool,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MachineLoad {
    pub load1: u32,
    pub load5: u32,
    pub load15: u32,
    pub running: u32,
    pub tasks: u32,
}

/// Machine data; a group is None when it could not be read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Machine {
    pub cpu: Option<MachineCpu>,
    pub processors: Vec<CpuTimes>,
    pub memory: Option<MachineMemory>,
    pub disk: Option<MachineDisk>,
    pub transports: Option<Transports>,
    pub adapters: Vec<NetworkAdapter>,
    pub load: Option<MachineLoad>,
}

pub type Passports = BTreeMap<Key, Arc<Passport>>;
pub type States = BTreeMap<Key, State>;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Environments {
    pub environments: Vec<LinuxEnvironmentInfo>,
    pub docker_containers: Vec<LinuxDockerContainerInfo>,
}

/// One tick's view: the conditional lists under their etags, and the metrics
/// of exactly the processes in `passports`, in its order.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub number: u64,
    pub sampled_at: u64,
    pub passports: Tagged<Arc<Passports>>,
    pub states: Tagged<Arc<States>>,
    pub environments: Tagged<Arc<Environments>>,
    pub rows: Arc<Vec<Row>>,
    pub machine: Arc<Machine>,
}

impl Snapshot {
    pub fn empty() -> Self {
        Self {
            number: 0,
            sampled_at: 0,
            passports: Tagged {
                etag: 0,
                value: Arc::default(),
            },
            states: Tagged {
                etag: 0,
                value: Arc::default(),
            },
            environments: Tagged {
                etag: 0,
                value: Arc::default(),
            },
            rows: Arc::default(),
            machine: Arc::default(),
        }
    }
}
