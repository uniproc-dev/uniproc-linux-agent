use std::fs;

use rustc_hash::FxHashMap;

use crate::docker::{self, Container, Docker};
use crate::model::Passport;
use crate::report::{LinuxDockerContainerInfo, LinuxEnvironmentInfo, LinuxEnvironmentKind};

#[derive(Clone, Copy)]
struct NamespaceRep {
    pid_ns: u64,
}

pub struct EnvironmentResolver {
    /// The pid namespace we run in. Unlike our *mount* namespace this really is
    /// the distro's: a process started through `wsl.exe` gets a mount namespace
    /// of its own but stays in the distro's pid namespace (`ps -p 1` shows its
    /// systemd). Anything sharing it is this same environment, however isolated
    /// its mounts happen to be.
    own_pid_ns: Option<u64>,
    /// Read once from our own filesystem. Going through
    /// `/proc/<pid>/root/etc/os-release` instead needs ptrace-level access to
    /// the target, which an unprivileged agent does not have for anything it
    /// does not own.
    distro_name: Option<String>,
    docker: Docker,
}

impl EnvironmentResolver {
    pub fn new() -> Self {
        Self {
            own_pid_ns: read_namespace_inode(std::process::id(), "pid"),
            distro_name: read_local_distro_name(),
            docker: Docker::start(),
        }
    }

    /// The distro's mount namespace, i.e. the one PID 1 lives in.
    ///
    /// Taken from the process list rather than `/proc/1/ns/mnt`, which is
    /// unreadable without privileges - the kernel already filled these in for
    /// us over eBPF. `local_pid == 1` is the init of *some* pid namespace (a
    /// container's init qualifies too), so it is only ours when the pid
    /// namespace matches.
    fn init_mnt_ns<'p>(&self, processes: impl Iterator<Item = &'p Passport>) -> Option<u64> {
        processes
            .into_iter()
            .find(|p| p.local_pid == 1 && Some(p.pid_ns) == self.own_pid_ns)
            .map(|p| p.mnt_ns)
    }

    pub fn resolve<'p>(
        &self,
        processes: impl Iterator<Item = &'p Passport> + Clone,
    ) -> (Vec<LinuxEnvironmentInfo>, Vec<LinuxDockerContainerInfo>) {
        let mut namespaces = FxHashMap::default();
        for process in processes.clone() {
            namespaces
                .entry(process.mnt_ns)
                .or_insert(NamespaceRep {
                    pid_ns: process.pid_ns,
                });
        }

        let docker = containers_of(&self.docker.containers(), processes.clone());
        let docker_by_ns: FxHashMap<u64, &LinuxDockerContainerInfo> =
            docker.iter().map(|info| (info.mnt_ns, info)).collect();

        let mut environments = Vec::with_capacity(namespaces.len());
        let mut namespace_keys: Vec<_> = namespaces.keys().copied().collect();
        namespace_keys.sort_unstable();

        let init_mnt_ns = self.init_mnt_ns(processes);

        for mnt_ns in namespace_keys {
            let rep = namespaces[&mnt_ns];
            // Ordered by how much the evidence is worth. Docker is positive
            // proof from the daemon itself; the distro is an identity we can
            // state rather than guess; the rest is decided by whether the pid
            // namespace is ours, which is what actually separates a *different*
            // environment from the same one merely holding its mounts apart.
            let kind = if let Some(container) = docker_by_ns.get(&mnt_ns) {
                LinuxEnvironmentKind::DockerContainer {
                    id: container.id.clone(),
                }
            } else if init_mnt_ns == Some(mnt_ns) {
                match &self.distro_name {
                    Some(name) => LinuxEnvironmentKind::CurrentDistro { name: name.clone() },
                    None => LinuxEnvironmentKind::Unknown,
                }
            } else if self.own_pid_ns.is_some() && Some(rep.pid_ns) == self.own_pid_ns {
                // Same pid namespace as us: a systemd unit hardened with
                // PrivateTmp=/ProtectSystem= gets a private mount namespace,
                // but it is not a separate environment - it is this one.
                LinuxEnvironmentKind::Unknown
            } else {
                LinuxEnvironmentKind::UnknownExternalNamespace
            };

            environments.push(LinuxEnvironmentInfo {
                mnt_ns,
                pid_ns: rep.pid_ns,
                kind,
            });
        }

        (environments, docker)
    }
}

/// The running containers some process is in, with the namespaces of the
/// container's init, or of its first process when init is not in sight.
/// Processes name their container through their cgroup, which the kernel
/// reports for every process in the VM; the daemon's `State.Pid` would be a
/// pid in the daemon's own namespace, another distro's under Docker Desktop.
fn containers_of<'p>(
    containers: &[Container],
    processes: impl Iterator<Item = &'p Passport>,
) -> Vec<LinuxDockerContainerInfo> {
    let running: FxHashMap<&str, &Container> =
        containers.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut found: FxHashMap<&str, (&Container, &Passport)> = FxHashMap::default();
    for process in processes {
        let Some(container) = process.container.as_deref().and_then(|id| running.get(id)) else {
            continue;
        };
        found
            .entry(container.id.as_str())
            .and_modify(|(_, seen)| {
                if process.local_pid == 1 {
                    *seen = process;
                }
            })
            .or_insert((container, process));
    }
    let mut out: Vec<LinuxDockerContainerInfo> = found
        .into_values()
        .map(|(container, process)| LinuxDockerContainerInfo {
            id: container.id.clone(),
            mnt_ns: process.mnt_ns,
            pid_ns: process.pid_ns,
            api_version: docker::API_VERSION.to_string(),
            raw_json: container.raw_json.clone(),
        })
        .collect();
    out.sort_by(|left, right| left.mnt_ns.cmp(&right.mnt_ns).then(left.id.cmp(&right.id)));
    out
}

/// The distro we are running in, read straight off our own filesystem.
///
/// This used to probe `/proc/<pid>/root/etc/os-release` of an arbitrary
/// process picked per namespace, which was wrong twice over: reading another
/// user's `/proc/<pid>/root` needs ptrace-level access, so success depended on
/// who happened to own that process; and every hardened systemd unit still sees
/// the real `/etc/os-release`, so a hit proved nothing about the namespace
/// being the distro. In practice that handed the distro's identity to whichever
/// namespace happened to have a representative we could read.
fn read_local_distro_name() -> Option<String> {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        let Ok(content) = fs::read_to_string(path) else {
            continue;
        };

        let pretty = parse_os_release_field(&content, "PRETTY_NAME");
        let name = parse_os_release_field(&content, "NAME");
        if pretty.is_some() || name.is_some() {
            return pretty.or(name);
        }
    }

    None
}

fn parse_os_release_field(content: &str, key: &str) -> Option<String> {
    let line = content.lines().find(|line| line.starts_with(key))?;
    let (_, value) = line.split_once('=')?;
    Some(value.trim().trim_matches('"').to_string())
}

pub fn read_namespace_inode(pid: u32, namespace: &str) -> Option<u64> {
    let target = fs::read_link(format!("/proc/{pid}/ns/{namespace}")).ok()?;
    let target = target.to_string_lossy();
    let start = target.find('[')? + 1;
    let end = target[start..].find(']')? + start;
    target[start..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Key;

    const ID: &str = "4f1c0d2a9b8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a";

    fn process(pid: u32, local_pid: u32, mnt_ns: u64, pid_ns: u64, container: Option<&str>) -> Passport {
        Passport {
            key: Key {
                pid,
                sequence_number: pid as u64,
            },
            view_pid: 0,
            parent_pid: 1,
            start_time: 0,
            name: String::new(),
            exe_path: String::new(),
            cmdline: Vec::new(),
            uid: 0,
            user: String::new(),
            local_pid,
            mnt_ns,
            pid_ns,
            cgroup: String::new(),
            container: container.map(str::to_owned),
        }
    }

    #[test]
    fn a_container_takes_the_namespaces_of_its_init_and_only_running_ones_count() {
        let containers = vec![Container {
            id: ID.into(),
            raw_json: "{}".into(),
        }];
        let processes = [
            process(10, 7, 900, 901, Some(ID)),
            process(11, 1, 800, 801, Some(ID)),
            process(12, 1, 700, 701, Some(&ID.replace('4', "5"))),
            process(13, 50, 100, 101, None),
        ];
        let found = containers_of(&containers, processes.iter());
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].mnt_ns, found[0].pid_ns), (800, 801));
        assert_eq!(found[0].raw_json, "{}");
    }
}
