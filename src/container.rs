use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::risk::RiskLevel;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub runtime: Option<String>,
    pub pids: Vec<u32>,
    pub process: Option<ProcessInfo>,
    pub cgroup_paths: Vec<String>,
    pub namespaces: NamespaceInfo,
    pub namespace_risk: NamespaceRisk,
    pub capabilities: CapabilityInfo,
    pub security: SecurityProfile,
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub name: Option<String>,
    pub command_line: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct NamespaceInfo {
    pub pid: Option<String>,
    pub mnt: Option<String>,
    pub net: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct NamespaceRisk {
    pub host_pid_namespace: bool,
    pub host_mount_namespace: bool,
    pub host_network_namespace: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilityInfo {
    pub effective_hex: Option<String>,
    pub has_cap_sys_admin: bool,
    pub has_cap_sys_module: bool,
    pub has_cap_sys_ptrace: bool,
    pub has_cap_net_admin: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityProfile {
    pub seccomp_mode: Option<u8>,
    pub no_new_privs: Option<bool>,
}

#[derive(Debug, Clone)]
struct ProcessCgroup {
    pid: u32,
    cgroup_paths: Vec<String>,
    container_id: String,
    runtime: Option<String>,
}

pub fn discover_containers() -> Vec<ContainerInfo> {
    let mut groups: BTreeMap<String, Vec<ProcessCgroup>> = BTreeMap::new();

    for entry in read_proc_entries() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };

        let Some(process) = read_process_cgroup(pid) else {
            continue;
        };

        groups
            .entry(process.container_id.clone())
            .or_default()
            .push(process);
    }

    groups
        .into_iter()
        .map(|(id, processes)| build_container_info(id, processes))
        .collect()
}

fn build_container_info(id: String, processes: Vec<ProcessCgroup>) -> ContainerInfo {
    let mut pids: Vec<u32> = processes.iter().map(|process| process.pid).collect();
    pids.sort_unstable();

    let mut cgroup_paths: Vec<String> = processes
        .iter()
        .flat_map(|process| process.cgroup_paths.clone())
        .collect();
    cgroup_paths.sort();
    cgroup_paths.dedup();

    let runtime = processes.iter().find_map(|process| process.runtime.clone());
    let first_pid = pids.first().copied();
    let process = first_pid.map(read_process_info);
    let namespaces = first_pid.map(read_namespaces).unwrap_or_default();
    let namespace_risk = namespace_risk(&namespaces);
    let capabilities = first_pid.map(read_capabilities).unwrap_or_default();
    let security = first_pid.map(read_security_profile).unwrap_or_default();

    let mut risk = RiskLevel::Low;
    let mut reasons = Vec::new();

    if namespace_risk.host_pid_namespace {
        risk = risk.max(RiskLevel::High);
        reasons.push("process appears to share the host PID namespace".to_string());
    }
    if namespace_risk.host_mount_namespace {
        risk = risk.max(RiskLevel::Medium);
        reasons.push("process appears to share the host mount namespace".to_string());
    }
    if namespace_risk.host_network_namespace {
        risk = risk.max(RiskLevel::Medium);
        reasons.push("process appears to share the host network namespace".to_string());
    }

    if matches!(security.seccomp_mode, Some(0)) {
        risk = risk.max(RiskLevel::High);
        reasons.push("representative process has seccomp disabled".to_string());
    } else if security.seccomp_mode.is_none() {
        risk = risk.max(RiskLevel::Medium);
        reasons.push("seccomp mode could not be read for representative process".to_string());
    }

    if matches!(security.no_new_privs, Some(false)) {
        risk = risk.max(RiskLevel::Medium);
        reasons.push("no_new_privs is not set on representative process".to_string());
    }

    if capabilities.has_cap_sys_admin {
        risk = RiskLevel::High;
        reasons.push("process has CAP_SYS_ADMIN effective".to_string());
    }
    if capabilities.has_cap_sys_module {
        risk = risk.max(RiskLevel::High);
        reasons.push("process has CAP_SYS_MODULE effective".to_string());
    }
    if capabilities.has_cap_sys_ptrace {
        risk = risk.max(RiskLevel::Medium);
        reasons.push("process has CAP_SYS_PTRACE effective".to_string());
    }
    if capabilities.has_cap_net_admin {
        risk = risk.max(RiskLevel::Medium);
        reasons.push("process has CAP_NET_ADMIN effective".to_string());
    }

    ContainerInfo {
        id,
        runtime,
        pids,
        process,
        cgroup_paths,
        namespaces,
        namespace_risk,
        capabilities,
        security,
        risk,
        reasons,
    }
}

fn read_proc_entries() -> Vec<fs::DirEntry> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries.filter_map(Result::ok).collect()
}

fn read_process_cgroup(pid: u32) -> Option<ProcessCgroup> {
    let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let cgroup_paths: Vec<String> = cgroup
        .lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path.to_string()))
        .collect();

    let mut best = None;
    for path in &cgroup_paths {
        if let Some((runtime, id)) = parse_container_id(path) {
            best = Some((runtime, id));
            break;
        }
    }

    let (runtime, container_id) = best?;

    Some(ProcessCgroup {
        pid,
        cgroup_paths,
        container_id,
        runtime,
    })
}

fn parse_container_id(path: &str) -> Option<(Option<String>, String)> {
    for segment in path.split('/') {
        let clean = segment
            .trim()
            .trim_start_matches("docker-")
            .trim_start_matches("cri-containerd-")
            .trim_start_matches("crio-")
            .trim_end_matches(".scope");

        if clean.len() >= 12 && clean.chars().all(|char| char.is_ascii_hexdigit()) {
            let runtime = if segment.contains("docker") || path.contains("/docker") {
                Some("docker".to_string())
            } else if segment.contains("containerd") || path.contains("containerd") {
                Some("containerd".to_string())
            } else if segment.contains("crio") || path.contains("crio") {
                Some("cri-o".to_string())
            } else {
                None
            };

            return Some((runtime, clean.to_string()));
        }
    }

    None
}

fn read_namespaces(pid: u32) -> NamespaceInfo {
    NamespaceInfo {
        pid: read_namespace_link(pid, "pid"),
        mnt: read_namespace_link(pid, "mnt"),
        net: read_namespace_link(pid, "net"),
        user: read_namespace_link(pid, "user"),
    }
}

fn namespace_risk(namespaces: &NamespaceInfo) -> NamespaceRisk {
    let host = read_namespaces(1);

    NamespaceRisk {
        host_pid_namespace: namespaces.pid.is_some() && namespaces.pid == host.pid,
        host_mount_namespace: namespaces.mnt.is_some() && namespaces.mnt == host.mnt,
        host_network_namespace: namespaces.net.is_some() && namespaces.net == host.net,
    }
}

fn read_namespace_link(pid: u32, namespace: &str) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}/ns/{namespace}"));
    fs::read_link(path)
        .ok()
        .map(|target| target.to_string_lossy().to_string())
}

fn read_capabilities(pid: u32) -> CapabilityInfo {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let effective_hex = status.lines().find_map(|line| {
        line.strip_prefix("CapEff:")
            .map(|value| value.trim().to_string())
    });

    let effective = effective_hex
        .as_deref()
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .unwrap_or(0);

    CapabilityInfo {
        effective_hex,
        has_cap_sys_admin: has_cap(effective, 21),
        has_cap_sys_module: has_cap(effective, 16),
        has_cap_sys_ptrace: has_cap(effective, 19),
        has_cap_net_admin: has_cap(effective, 12),
    }
}

fn read_process_info(pid: u32) -> ProcessInfo {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();

    ProcessInfo {
        pid,
        ppid: read_status_u32(&status, "PPid:"),
        uid: read_status_first_u32(&status, "Uid:"),
        gid: read_status_first_u32(&status, "Gid:"),
        name: read_status_string(&status, "Name:"),
        command_line: read_cmdline(pid),
    }
}

fn read_security_profile(pid: u32) -> SecurityProfile {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();

    SecurityProfile {
        seccomp_mode: read_status_u32(&status, "Seccomp:")
            .and_then(|value| u8::try_from(value).ok()),
        no_new_privs: read_status_u32(&status, "NoNewPrivs:").map(|value| value != 0),
    }
}

fn read_status_string(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_string()))
}

fn read_status_u32(status: &str, key: &str) -> Option<u32> {
    read_status_string(status, key).and_then(|value| value.parse::<u32>().ok())
}

fn read_status_first_u32(status: &str, key: &str) -> Option<u32> {
    read_status_string(status, key)
        .and_then(|value| value.split_whitespace().next().map(str::to_string))
        .and_then(|value| value.parse::<u32>().ok())
}

fn read_cmdline(pid: u32) -> Option<String> {
    let bytes = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let parts = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>();
    (!parts.is_empty()).then_some(parts.join(" "))
}

fn has_cap(mask: u64, cap: u8) -> bool {
    mask & (1_u64 << cap) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_cgroup_id() {
        let id = "b9f10f0f84a2c6f3b7a95d4e43c66f5a3f4f6e0b1a2c3d4e5f60718293a4b5c6";
        let path = format!("/system.slice/docker-{id}.scope");

        let parsed = parse_container_id(&path);

        assert_eq!(parsed, Some((Some("docker".to_string()), id.to_string())));
    }

    #[test]
    fn parses_containerd_cgroup_id() {
        let id = "4f5a3f4f6e0b1a2c3d4e5f60718293a4b5c6b9f10f0f84a2c6f3b7a95d4e43c66";
        let path = format!("/kubepods.slice/kubepods-burstable.slice/cri-containerd-{id}.scope");

        let parsed = parse_container_id(&path);

        assert_eq!(
            parsed,
            Some((Some("containerd".to_string()), id.to_string()))
        );
    }

    #[test]
    fn ignores_non_container_cgroup_path() {
        assert_eq!(
            parse_container_id("/user.slice/user-501.slice/session-1.scope"),
            None
        );
    }

    #[test]
    fn checks_capability_bits() {
        let cap_sys_admin = 1_u64 << 21;
        let cap_net_admin = 1_u64 << 12;
        let mask = cap_sys_admin | cap_net_admin;

        assert!(has_cap(mask, 21));
        assert!(has_cap(mask, 12));
        assert!(!has_cap(mask, 16));
    }

    #[test]
    fn parses_process_status_fields() {
        let status = "Name:\tnginx\nPPid:\t12\nUid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nSeccomp:\t2\nNoNewPrivs:\t1\n";

        assert_eq!(
            read_status_string(status, "Name:"),
            Some("nginx".to_string())
        );
        assert_eq!(read_status_u32(status, "PPid:"), Some(12));
        assert_eq!(read_status_first_u32(status, "Uid:"), Some(1000));
        assert_eq!(read_status_first_u32(status, "Gid:"), Some(1001));
        assert_eq!(read_status_u32(status, "Seccomp:"), Some(2));
        assert_eq!(read_status_u32(status, "NoNewPrivs:"), Some(1));
    }
}
