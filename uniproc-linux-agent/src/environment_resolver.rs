use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use rustc_hash::FxHashMap;
use serde_json::Value;
use uniproc_protocol::{
    LinuxDockerContainerInfo, LinuxEnvironmentInfo, LinuxEnvironmentKind, ProcessStats,
};

const DOCKER_API_VERSION: &str = "v1.41";
const DOCKER_SOCKET_PATH: &str = "/var/run/docker.sock";

#[derive(Clone, Copy)]
struct NamespaceRep {
    pid_ns: u64,
    global_pid: u32,
}

pub struct EnvironmentResolver {
    current_mnt_ns: Option<u64>,
}

impl EnvironmentResolver {
    pub fn new() -> Self {
        Self {
            current_mnt_ns: read_namespace_inode(std::process::id(), "mnt"),
        }
    }

    pub fn resolve(
        &self,
        processes: &[ProcessStats],
    ) -> (Vec<LinuxEnvironmentInfo>, Vec<LinuxDockerContainerInfo>) {
        let mut namespaces = FxHashMap::default();
        for process in processes {
            namespaces
                .entry(process.mnt_ns)
                .or_insert(NamespaceRep {
                    pid_ns: process.pid_ns,
                    global_pid: process.global_pid,
                });
        }

        let docker = resolve_docker_containers(&namespaces).unwrap_or_default();
        let docker_by_ns: FxHashMap<u64, &LinuxDockerContainerInfo> =
            docker.iter().map(|info| (info.mnt_ns, info)).collect();

        let mut environments = Vec::with_capacity(namespaces.len());
        let mut namespace_keys: Vec<_> = namespaces.keys().copied().collect();
        namespace_keys.sort_unstable();

        for mnt_ns in namespace_keys {
            let rep = namespaces[&mnt_ns];
            let kind = if let Some(container) = docker_by_ns.get(&mnt_ns) {
                LinuxEnvironmentKind::DockerContainer {
                    id: container.id.clone(),
                }
            } else if let Some(name) = resolve_distro_name(rep.global_pid) {
                LinuxEnvironmentKind::CurrentDistro { name }
            } else if self.current_mnt_ns.is_some() && self.current_mnt_ns != Some(mnt_ns) {
                LinuxEnvironmentKind::UnknownExternalNamespace
            } else {
                LinuxEnvironmentKind::Unknown
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

fn resolve_docker_containers(
    namespaces: &FxHashMap<u64, NamespaceRep>,
) -> anyhow::Result<Vec<LinuxDockerContainerInfo>> {
    if namespaces.is_empty() {
        return Ok(Vec::new());
    }

    let raw_list = docker_get(&format!("/{DOCKER_API_VERSION}/containers/json?all=1"))?;
    let list: Value = serde_json::from_str(&raw_list)?;

    let mut out = Vec::new();
    let Some(containers) = list.as_array() else {
        return Ok(out);
    };

    for container in containers {
        let Some(id) = container.get("Id").and_then(Value::as_str) else {
            continue;
        };

        let raw_json = match docker_get(&format!("/{DOCKER_API_VERSION}/containers/{id}/json")) {
            Ok(raw_json) => raw_json,
            Err(_) => continue,
        };

        let inspect: Value = match serde_json::from_str(&raw_json) {
            Ok(value) => value,
            Err(_) => continue,
        };

        let pid = inspect
            .get("State")
            .and_then(|state| state.get("Pid"))
            .and_then(Value::as_u64)
            .unwrap_or_default() as u32;
        if pid == 0 {
            continue;
        }

        let Some(mnt_ns) = read_namespace_inode(pid, "mnt") else {
            continue;
        };
        if !namespaces.contains_key(&mnt_ns) {
            continue;
        }

        let pid_ns = read_namespace_inode(pid, "pid").unwrap_or_default();
        out.push(LinuxDockerContainerInfo {
            id: id.to_string(),
            mnt_ns,
            pid_ns,
            api_version: DOCKER_API_VERSION.to_string(),
            raw_json,
        });
    }

    out.sort_by(|left, right| left.mnt_ns.cmp(&right.mnt_ns).then(left.id.cmp(&right.id)));
    Ok(out)
}

fn docker_get(path: &str) -> anyhow::Result<String> {
    let mut stream = UnixStream::connect(DOCKER_SOCKET_PATH)?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n"
    )?;
    stream.shutdown(std::net::Shutdown::Write)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;

    let Some(split_at) = response.windows(4).position(|w| w == b"\r\n\r\n") else {
        anyhow::bail!("invalid docker response");
    };

    let (head, body) = response.split_at(split_at + 4);
    let head = std::str::from_utf8(head)?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        anyhow::bail!("docker api error: {}", head.lines().next().unwrap_or("?"));
    }

    Ok(String::from_utf8(body.to_vec())?)
}

fn resolve_distro_name(pid: u32) -> Option<String> {
    for path in [
        format!("/proc/{pid}/root/etc/os-release"),
        format!("/proc/{pid}/root/usr/lib/os-release"),
    ] {
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

fn read_namespace_inode(pid: u32, namespace: &str) -> Option<u64> {
    let target = fs::read_link(format!("/proc/{pid}/ns/{namespace}")).ok()?;
    let target = target.to_string_lossy();
    let start = target.find('[')? + 1;
    let end = target[start..].find(']')? + start;
    target[start..end].parse().ok()
}
