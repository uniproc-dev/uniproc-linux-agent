use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustc_hash::FxHashMap;
use uniproc_agent_kit::{Epoch, Versioned};

use crate::bpf::{BpfAgent, Sample};
use crate::environment_resolver::EnvironmentResolver;
use crate::model::{
    Environments, Key, Machine, Passport, Passports, Row, SchedPolicy, Snapshot, State, States,
    TaskState,
};
use crate::procfs::{self, Users};
use crate::tasks::{ProcessRecord, Task};

const ENVIRONMENTS_EVERY: Duration = Duration::from_secs(5);

/// Turns what the kernel holds into snapshots, keeping each list's etag
/// until the list moves.
pub struct Snapshots {
    agent: BpfAgent<'static>,
    number: u64,
    passports: Versioned<Arc<Passports>>,
    states: Versioned<Arc<States>>,
    environments: Versioned<Arc<Environments>>,
    known: FxHashMap<Key, (u64, Arc<Passport>)>,
    users: Users,
    resolver: EnvironmentResolver,
    resolved: Option<(Instant, BTreeSet<(u64, u64)>)>,
    page_size: u64,
    user_hz: u64,
}

impl Snapshots {
    pub fn new(agent: BpfAgent<'static>) -> Self {
        let epoch = Epoch::new();
        Self {
            agent,
            number: 0,
            passports: Versioned::new(epoch, Arc::default()),
            states: Versioned::new(epoch, Arc::default()),
            environments: Versioned::new(epoch, Arc::default()),
            known: FxHashMap::default(),
            users: Users::default(),
            resolver: EnvironmentResolver::new(),
            resolved: None,
            page_size: procfs::page_size(),
            user_hz: procfs::user_hz(),
        }
    }

    pub fn take(&mut self) -> anyhow::Result<Snapshot> {
        let sample = self.agent.sample()?;
        self.users.refresh();
        let tasks: BTreeMap<Key, &Task> = sample.tasks.iter().map(|t| (key_of(&t.process), t)).collect();

        let boot_epoch = procfs::boot_epoch_ns();
        let mut passports = Passports::new();
        let mut states = States::new();
        for (&key, task) in &tasks {
            passports.insert(key, self.passport(key, &task.process, boot_epoch));
            states.insert(key, state_of(key, &task.process));
        }
        self.known.retain(|key, _| passports.contains_key(key));

        let rows = tasks
            .iter()
            .map(|(&key, task)| self.row(key, task, &sample))
            .collect();

        self.refresh_environments(&passports);
        self.passports.set(Arc::new(passports));
        self.states.set(Arc::new(states));

        self.number += 1;
        Ok(Snapshot {
            number: self.number,
            sampled_at: procfs::boottime_ns() / 100,
            passports: self.passports.get().clone(),
            states: self.states.get().clone(),
            environments: self.environments.get().clone(),
            rows: Arc::new(rows),
            machine: Arc::new(self.machine(sample.transports)),
        })
    }

    fn passport(&mut self, key: Key, p: &ProcessRecord, boot_epoch: u64) -> Arc<Passport> {
        if let Some((exec_id, known)) = self.known.get_mut(&key)
            && *exec_id == p.exec_id
        {
            let name = p.comm();
            if known.parent_pid != p.ppid || known.name != name {
                let mut moved = Passport::clone(known);
                moved.parent_pid = p.ppid;
                moved.name = name;
                *known = Arc::new(moved);
            }
            return known.clone();
        }
        let visible = p.view_pid != 0;
        let passport = Arc::new(Passport {
            key,
            view_pid: p.view_pid,
            parent_pid: p.ppid,
            start_time: (boot_epoch + p.start_boottime) / 100,
            name: p.comm(),
            exe_path: if visible { procfs::exe_path(p.view_pid) } else { String::new() },
            cmdline: if visible { procfs::cmdline(p.view_pid) } else { Vec::new() },
            uid: p.uid,
            user: self.users.name(p.uid),
            local_pid: p.local_pid,
            mnt_ns: p.mnt_ns,
            pid_ns: p.pid_ns,
            cgroup: if visible { procfs::cgroup(p.view_pid) } else { String::new() },
        });
        self.known.insert(key, (p.exec_id, passport.clone()));
        passport
    }

    fn row(&self, key: Key, task: &Task, sample: &Sample) -> Row {
        let p = &task.process;
        let c = &task.counters;
        let page = self.page_size;
        let resident = p.rss_file + p.rss_anon + p.rss_shmem;
        Row {
            key,
            cpu_user_time: c.utime / 100,
            cpu_kernel_time: c.stime / 100,
            cpu_run_time: c.runtime / 100,
            resident_set: resident * page,
            resident_anon: p.rss_anon * page,
            resident_file: p.rss_file * page,
            resident_shmem: p.rss_shmem * page,
            peak_resident_set: p.hiwater_rss.max(resident) * page,
            virtual_size: p.total_vm * page,
            peak_virtual_size: p.hiwater_vm.max(p.total_vm) * page,
            swap: p.swap * page,
            minor_faults: c.min_flt,
            major_faults: c.maj_flt,
            threads: p.threads,
            voluntary_context_switches: c.nvcsw,
            involuntary_context_switches: c.nivcsw,
            io_read_ops: c.syscr,
            io_write_ops: c.syscw,
            io_read_bytes: c.rchar,
            io_write_bytes: c.wchar,
            disk_read_bytes: c.read_bytes,
            disk_write_bytes: c.write_bytes,
            probed: sample.probed.get(&p.tgid).copied(),
        }
    }

    fn refresh_environments(&mut self, passports: &Passports) {
        let namespaces: BTreeSet<(u64, u64)> =
            passports.values().map(|p| (p.mnt_ns, p.pid_ns)).collect();
        let due = match &self.resolved {
            Some((at, known)) => *known != namespaces || at.elapsed() >= ENVIRONMENTS_EVERY,
            None => true,
        };
        if !due {
            return;
        }
        let (environments, docker_containers) =
            self.resolver.resolve(passports.values().map(|p| p.as_ref()));
        self.environments.set(Arc::new(Environments {
            environments,
            docker_containers,
        }));
        self.resolved = Some((Instant::now(), namespaces));
    }

    fn machine(&self, transports: Option<crate::model::Transports>) -> Machine {
        let cpu = procfs::cpu(self.user_hz);
        Machine {
            cpu: cpu.as_ref().map(|c| c.machine),
            processors: cpu.map(|c| c.processors).unwrap_or_default(),
            memory: procfs::memory(),
            disk: procfs::disk(),
            transports,
            adapters: procfs::adapters(),
            load: procfs::load(),
        }
    }
}

fn key_of(p: &ProcessRecord) -> Key {
    Key {
        pid: p.tgid,
        sequence_number: p.start_boottime,
    }
}

fn state_of(key: Key, p: &ProcessRecord) -> State {
    State {
        key,
        state: task_state(p.state, p.exit_state),
        nice: p.static_prio - 120,
        policy: sched_policy(p.policy),
        rt_priority: p.rt_priority,
    }
}

const TASK_INTERRUPTIBLE: u32 = 0x1;
const TASK_UNINTERRUPTIBLE: u32 = 0x2;
const TASK_STOPPED: u32 = 0x4;
const TASK_TRACED: u32 = 0x8;
const EXIT_DEAD: u32 = 0x10;
const EXIT_ZOMBIE: u32 = 0x20;
const TASK_PARKED: u32 = 0x40;
const TASK_NOLOAD: u32 = 0x400;
const TASK_REPORT: u32 = 0x7f;

fn task_state(state: u32, exit_state: u32) -> TaskState {
    if state & (TASK_UNINTERRUPTIBLE | TASK_NOLOAD) == TASK_UNINTERRUPTIBLE | TASK_NOLOAD {
        return TaskState::Idle;
    }
    let report = (state & TASK_REPORT) | exit_state;
    if report == 0 {
        return TaskState::Running;
    }
    match 1u32 << (31 - report.leading_zeros()) {
        TASK_INTERRUPTIBLE => TaskState::Sleeping,
        TASK_UNINTERRUPTIBLE => TaskState::DiskSleep,
        TASK_STOPPED => TaskState::Stopped,
        TASK_TRACED => TaskState::TracingStop,
        EXIT_DEAD | EXIT_ZOMBIE => TaskState::Zombie,
        TASK_PARKED => TaskState::Idle,
        _ => TaskState::Unknown,
    }
}

fn sched_policy(policy: u32) -> SchedPolicy {
    match policy {
        0 => SchedPolicy::Other,
        1 => SchedPolicy::Fifo,
        2 => SchedPolicy::Rr,
        3 => SchedPolicy::Batch,
        5 => SchedPolicy::Idle,
        6 => SchedPolicy::Deadline,
        _ => SchedPolicy::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_states_follow_proc_pid_stat() {
        assert_eq!(task_state(0, 0), TaskState::Running);
        assert_eq!(task_state(TASK_INTERRUPTIBLE, 0), TaskState::Sleeping);
        assert_eq!(task_state(TASK_UNINTERRUPTIBLE, 0), TaskState::DiskSleep);
        assert_eq!(task_state(TASK_UNINTERRUPTIBLE | TASK_NOLOAD, 0), TaskState::Idle);
        assert_eq!(task_state(0x100 | TASK_STOPPED, 0), TaskState::Stopped);
        assert_eq!(task_state(TASK_TRACED, 0), TaskState::TracingStop);
        assert_eq!(task_state(0, EXIT_ZOMBIE), TaskState::Zombie);
    }

    #[test]
    fn policies_map_by_number() {
        assert_eq!(sched_policy(0), SchedPolicy::Other);
        assert_eq!(sched_policy(2), SchedPolicy::Rr);
        assert_eq!(sched_policy(4), SchedPolicy::Unknown);
        assert_eq!(sched_policy(6), SchedPolicy::Deadline);
    }
}
