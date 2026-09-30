use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;

pub const API_VERSION: &str = "v1.41";
const SOCKET: &str = "/var/run/docker.sock";
const POLL_EVERY: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const DEADLINE: Duration = Duration::from_secs(5);
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// A running container and the daemon's inspect answer for it.
#[derive(Clone, Debug, PartialEq)]
pub struct Container {
    pub id: String,
    pub raw_json: String,
}

/// The running containers, as a thread of its own last heard from the daemon.
#[derive(Clone, Default)]
pub struct Docker {
    containers: Arc<Mutex<Arc<Vec<Container>>>>,
}

impl Docker {
    /// Polls the daemon every few seconds on a thread named `docker`.
    pub fn start() -> Self {
        let docker = Self::default();
        let shared = docker.containers.clone();
        let spawned = std::thread::Builder::new().name("docker".into()).spawn(move || {
            let mut known = HashMap::new();
            loop {
                let containers = match poll(Path::new(SOCKET), &mut known) {
                    Ok(()) => known.values().cloned().collect(),
                    Err(_) => {
                        known.clear();
                        Vec::new()
                    }
                };
                *shared.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(containers);
                std::thread::sleep(POLL_EVERY);
            }
        });
        if let Err(e) = spawned {
            tracing::warn!("docker: no thread to poll the daemon: {e}");
        }
        docker
    }

    pub fn containers(&self) -> Arc<Vec<Container>> {
        self.containers.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

/// Lists the running containers and inspects the ones not inspected yet.
fn poll(socket: &Path, known: &mut HashMap<String, Container>) -> anyhow::Result<()> {
    let list: Value = serde_json::from_str(&get(socket, &format!("/{API_VERSION}/containers/json"))?)?;
    let ids: Vec<&str> = list
        .as_array()
        .map(|containers| containers.iter().filter_map(|c| c.get("Id")?.as_str()).collect())
        .unwrap_or_default();
    known.retain(|id, _| ids.contains(&id.as_str()));
    for id in ids {
        if known.contains_key(id) {
            continue;
        }
        let Ok(raw_json) = get(socket, &format!("/{API_VERSION}/containers/{id}/json")) else {
            continue;
        };
        known.insert(
            id.to_owned(),
            Container {
                id: id.to_owned(),
                raw_json,
            },
        );
    }
    Ok(())
}

/// One HTTP/1.0 GET over the daemon's socket, so the answer is never chunked
/// by a daemon that honours the version; a chunked one is decoded anyway.
fn get(socket: &Path, path: &str) -> anyhow::Result<String> {
    let deadline = Instant::now() + DEADLINE;
    let mut stream = UnixStream::connect(socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    write!(stream, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n")?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.len() > MAX_RESPONSE {
            anyhow::bail!("docker answer larger than {MAX_RESPONSE} bytes");
        }
        if Instant::now() > deadline {
            anyhow::bail!("docker did not answer within {DEADLINE:?}");
        }
    }
    body(&response)
}

fn body(response: &[u8]) -> anyhow::Result<String> {
    let split_at = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("docker answer has no header end"))?;
    let (head, body) = response.split_at(split_at + 4);
    let head = std::str::from_utf8(head)?;
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        anyhow::bail!("docker api error: {status}");
    }
    let chunked = head.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = if chunked { dechunk(body)? } else { body.to_vec() };
    Ok(String::from_utf8(body)?)
}

fn dechunk(mut body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow::anyhow!("chunk size line never ends"))?;
        let size_line = std::str::from_utf8(&body[..line_end])?;
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16)?;
        body = &body[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if body.len() < size + 2 {
            anyhow::bail!("chunk cut short");
        }
        out.extend_from_slice(&body[..size]);
        body = &body[size + 2..];
    }
}

/// The 64-hex container id in a cgroup's last component, as docker names it
/// under either cgroup driver: `docker-<id>.scope` or `<id>`.
pub fn container_id(cgroup_leaf: &str) -> Option<&str> {
    cgroup_leaf
        .split(|c: char| !c.is_ascii_hexdigit())
        .find(|part| part.len() == 64)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    use super::*;

    const ID: &str = "4f1c0d2a9b8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a";

    #[test]
    fn a_container_id_comes_out_of_either_cgroup_driver() {
        assert_eq!(container_id(&format!("docker-{ID}.scope")), Some(ID));
        assert_eq!(container_id(ID), Some(ID));
        assert_eq!(container_id("init.scope"), None);
        assert_eq!(container_id("user@1000.service"), None);
    }

    #[test]
    fn a_chunked_answer_is_decoded() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n[{\"I\r\n9;x=y\r\nd\":\"abc\"}\r\n1\r\n]\r\n0\r\n\r\n";
        assert_eq!(body(response).unwrap(), r#"[{"Id":"abc"}]"#);
    }

    #[test]
    fn a_plain_answer_and_an_error_status() {
        assert_eq!(body(b"HTTP/1.0 200 OK\r\n\r\n[]").unwrap(), "[]");
        assert!(body(b"HTTP/1.1 404 Not Found\r\n\r\n{}").is_err());
        assert!(body(b"garbage").is_err());
    }

    fn serve(socket: &Path, answers: Vec<(&'static str, String)>) -> std::thread::JoinHandle<Vec<String>> {
        let listener = UnixListener::bind(socket).unwrap();
        std::thread::spawn(move || {
            let mut requests = Vec::new();
            for (expected, answer) in answers {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 1024];
                let read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..read]).into_owned();
                assert!(request.contains(expected), "{request}");
                assert!(request.contains("HTTP/1.0"), "{request}");
                stream.write_all(answer.as_bytes()).unwrap();
                requests.push(request);
            }
            requests
        })
    }

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ula-docker-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn running_containers_are_inspected_once() {
        let dir = scratch();
        let socket = dir.join("docker.sock");
        let list = format!("HTTP/1.0 200 OK\r\n\r\n[{{\"Id\":\"{ID}\"}}]");
        let inspect = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_string();
        let server = serve(&socket, vec![("/containers/json", list.clone()), ("/json", inspect), ("/containers/json", list)]);

        let mut known = HashMap::new();
        poll(&socket, &mut known).unwrap();
        assert_eq!(known[ID].raw_json, "{}");
        poll(&socket, &mut known).unwrap();
        assert_eq!(server.join().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_silent_daemon_times_out() {
        let dir = scratch();
        let socket = dir.join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let hold = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            std::thread::sleep(IO_TIMEOUT + Duration::from_millis(500));
            drop(stream);
        });
        let started = Instant::now();
        assert!(get(&socket, "/_ping").is_err());
        assert!(started.elapsed() < IO_TIMEOUT + Duration::from_millis(400));
        hold.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
