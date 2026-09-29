#[derive(Debug, Clone, PartialEq)]
pub enum LinuxEnvironmentKind {
    Unknown,
    CurrentDistro { name: String },
    DockerContainer { id: String },
    UnknownExternalNamespace,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinuxEnvironmentInfo {
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub kind: LinuxEnvironmentKind,
}

#[derive(Debug, Clone, PartialEq)]
pub struct LinuxDockerContainerInfo {
    pub id: String,
    pub mnt_ns: u64,
    pub pid_ns: u64,
    pub api_version: String,
    pub raw_json: String,
}
