use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::risk::RiskLevel;

#[derive(Debug, Clone)]
pub struct ContainerInfo {
    pub id: String,
    pub runtime: Option<String>,
    pub pids: Vec<u32>,
    pub cgroup_paths: Vec<String>,
    pub namespaces: NamespaceInfo,
    pub capabilities: CapabilityInfo,
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct NamespaceInfo {
    pub pid: Option<String>,
    pub mnt: Option<String>,
    pub net: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct CapabilityInfo {
    pub effective_hex: Option<String>,
    pub has_cap_sys_admin: bool,
    pub has_cap_sys_module: bool,
    pub has_cap_sys_ptrace: bool,
    pub has_cap_net_admin: bool,
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
    let namespaces = first_pid.map(read_namespaces).unwrap_or_default();
    let capabilities = first_pid.map(read_capabilities).unwrap_or_default();

    let mut risk = RiskLevel::Low;
    let mut reasons = Vec::new();

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
        cgroup_paths,
        namespaces,
        capabilities,
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
}
