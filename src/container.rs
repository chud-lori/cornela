use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::event::RuntimeEvent;
use crate::risk::{RiskAssessment, RiskLevel};

#[allow(dead_code)]
const ENRICHMENT_TTL: Duration = Duration::from_secs(30);
#[allow(dead_code)]
const ENRICHMENT_SWEEP_INTERVAL: Duration = Duration::from_secs(5);

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
    pub mounts: MountRisk,
    pub runtime_config: RuntimeConfig,
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

#[derive(Debug, Clone, Default)]
pub struct MountRisk {
    pub host_root_mounted: bool,
    pub docker_socket_mounted: bool,
    pub proc_mounted_rw: bool,
    pub sys_mounted_rw: bool,
    pub suspicious_mounts: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimeConfig {
    pub privileged: Option<bool>,
    pub seccomp_profile: Option<String>,
    pub configured_capabilities: Vec<String>,
    pub host_pid: Option<bool>,
    pub host_network: Option<bool>,
    pub host_ipc: Option<bool>,
    pub source: Option<String>,
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

    // Read host namespaces (PID 1) once and reuse across all containers.
    // namespace_risk previously re-read /proc/1/ns/* for every container,
    // costing 4N readlinks on hosts with many containers.
    let host_namespaces = read_namespaces(1);

    groups
        .into_iter()
        .map(|(id, processes)| build_container_info(id, processes, &host_namespaces))
        .collect()
}

#[allow(dead_code)]
pub fn enrich_event(event: &mut RuntimeEvent) {
    let fields = read_enrichment(event.pid);
    apply_enrichment(event, &fields);
}

#[derive(Debug, Clone, Default)]
pub struct EnrichedFields {
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub command_line: Option<String>,
    pub pid_namespace: Option<String>,
    pub mount_namespace: Option<String>,
    pub network_namespace: Option<String>,
    pub container_id: Option<String>,
    pub cgroup_path: Option<String>,
}

// Caches per-tgid /proc lookups for the duration of a monitor run. Without
// this, every ringbuf event triggers ~6 syscalls and 4 file reads on
// /proc/<pid>/{status,cgroup,cmdline,ns/*} — and the same long-lived process
// pays that cost on every event it generates. The cache is invalidated when
// a ProcessExec event is observed for that pid (cmdline/namespaces may have
// just changed) and is swept periodically to bound memory.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct EnrichmentCache {
    entries: HashMap<u32, CacheEntry>,
    last_sweep: Option<Instant>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct CacheEntry {
    inserted: Instant,
    starttime: u64,
    fields: EnrichedFields,
}

#[allow(dead_code)]
impl EnrichmentCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn invalidate(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    pub fn enrich(&mut self, event: &mut RuntimeEvent) {
        self.maybe_sweep();
        let now = Instant::now();

        // Validate against /proc/<pid>/stat starttime so that a recycled pid
        // (within the TTL) is not served stale enrichment from the prior
        // process. Reading stat is one small file vs. the 6+ reads done by
        // read_enrichment, so the cache still pays for itself on hits.
        let Some(starttime) = read_process_starttime(event.pid) else {
            // Process is gone — cannot verify identity, so do not apply
            // any cached or freshly-read fields. The event keeps whatever
            // the BPF program already set.
            self.entries.remove(&event.pid);
            return;
        };

        let fresh = self.entries.get(&event.pid).is_some_and(|entry| {
            entry.starttime == starttime && now.duration_since(entry.inserted) <= ENRICHMENT_TTL
        });

        if !fresh {
            let fields = read_enrichment(event.pid);
            self.entries.insert(
                event.pid,
                CacheEntry {
                    inserted: now,
                    starttime,
                    fields,
                },
            );
        }
        if let Some(entry) = self.entries.get(&event.pid) {
            apply_enrichment(event, &entry.fields);
        }
    }

    fn maybe_sweep(&mut self) {
        let now = Instant::now();
        let due = self
            .last_sweep
            .is_none_or(|prev| now.duration_since(prev) >= ENRICHMENT_SWEEP_INTERVAL);
        if !due {
            return;
        }
        self.entries
            .retain(|_, entry| now.duration_since(entry.inserted) <= ENRICHMENT_TTL);
        self.last_sweep = Some(now);
    }
}

fn read_enrichment(pid: u32) -> EnrichedFields {
    let process = read_process_info(pid);
    let namespaces = read_namespaces(pid);
    let process_cgroup = read_process_cgroup(pid);

    let (container_id, cgroup_path) = match process_cgroup {
        Some(cgroup) => (
            Some(cgroup.container_id),
            cgroup.cgroup_paths.into_iter().next(),
        ),
        None => (None, None),
    };

    EnrichedFields {
        ppid: process.ppid,
        uid: process.uid,
        gid: process.gid,
        command_line: process.command_line,
        pid_namespace: namespaces.pid,
        mount_namespace: namespaces.mnt,
        network_namespace: namespaces.net,
        container_id,
        cgroup_path,
    }
}

fn apply_enrichment(event: &mut RuntimeEvent, fields: &EnrichedFields) {
    event.ppid = fields.ppid;
    event.uid = event.uid.or(fields.uid);
    event.gid = event.gid.or(fields.gid);
    event.command_line = fields.command_line.clone();
    event.pid_namespace = fields.pid_namespace.clone();
    event.mount_namespace = fields.mount_namespace.clone();
    event.network_namespace = fields.network_namespace.clone();
    if let Some(id) = &fields.container_id {
        event.container_id = Some(id.clone());
        event.cgroup_path = fields.cgroup_path.clone();
    }
}

fn build_container_info(
    id: String,
    processes: Vec<ProcessCgroup>,
    host_namespaces: &NamespaceInfo,
) -> ContainerInfo {
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
    let namespace_risk = namespace_risk(&namespaces, host_namespaces);
    let capabilities = first_pid.map(read_capabilities).unwrap_or_default();
    let security = first_pid.map(read_security_profile).unwrap_or_default();
    let mounts = first_pid.map(read_mount_risk).unwrap_or_default();
    let runtime_config = inspect_runtime_config(runtime.as_deref(), &id);

    let mut assessment = RiskAssessment::new();

    if namespace_risk.host_pid_namespace {
        assessment.add(
            RiskLevel::High,
            "process appears to share the host PID namespace",
        );
    }
    if namespace_risk.host_mount_namespace {
        assessment.add(
            RiskLevel::Medium,
            "process appears to share the host mount namespace",
        );
    }
    if namespace_risk.host_network_namespace {
        assessment.add(
            RiskLevel::Medium,
            "process appears to share the host network namespace",
        );
    }

    if matches!(security.seccomp_mode, Some(0)) {
        assessment.add(
            RiskLevel::High,
            "representative process has seccomp disabled",
        );
    } else if security.seccomp_mode.is_none() {
        assessment.add(
            RiskLevel::Medium,
            "seccomp mode could not be read for representative process",
        );
    }

    if matches!(security.no_new_privs, Some(false)) {
        assessment.add(
            RiskLevel::Medium,
            "no_new_privs is not set on representative process",
        );
    }

    if capabilities.has_cap_sys_admin {
        assessment.add(RiskLevel::High, "process has CAP_SYS_ADMIN effective");
    }
    if capabilities.has_cap_sys_module {
        assessment.add(RiskLevel::High, "process has CAP_SYS_MODULE effective");
    }
    if capabilities.has_cap_sys_ptrace {
        assessment.add(RiskLevel::Medium, "process has CAP_SYS_PTRACE effective");
    }
    if capabilities.has_cap_net_admin {
        assessment.add(RiskLevel::Medium, "process has CAP_NET_ADMIN effective");
    }

    if mounts.host_root_mounted {
        assessment.add(RiskLevel::High, "host root filesystem appears mounted");
    }
    if mounts.docker_socket_mounted {
        assessment.add(RiskLevel::High, "Docker socket appears mounted");
    }
    if mounts.proc_mounted_rw {
        assessment.add(RiskLevel::Medium, "/proc appears mounted read-write");
    }
    if mounts.sys_mounted_rw {
        assessment.add(RiskLevel::Medium, "/sys appears mounted read-write");
    }
    if matches!(runtime_config.privileged, Some(true)) {
        assessment.add(RiskLevel::High, "container runtime reports privileged mode");
    }
    if matches!(runtime_config.host_pid, Some(true)) {
        assessment.add(
            RiskLevel::High,
            "container runtime reports host PID namespace",
        );
    }
    if matches!(runtime_config.host_network, Some(true)) {
        assessment.add(
            RiskLevel::Medium,
            "container runtime reports host network namespace",
        );
    }
    if runtime_config
        .seccomp_profile
        .as_deref()
        .is_some_and(|profile| profile == "unconfined")
    {
        assessment.add(
            RiskLevel::High,
            "container runtime reports seccomp unconfined",
        );
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
        mounts,
        runtime_config,
        risk: assessment.level,
        reasons: assessment.reasons(),
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

// Runtime-prefixed segment patterns we recognise. Order matters: longer/more
// specific prefixes (cri-containerd-, crio-conmon-) must come before shorter
// ones that they would otherwise match.
const RUNTIME_PREFIXES: &[(&str, &str)] = &[
    ("cri-containerd-", "containerd"),
    ("crio-conmon-", "cri-o"),
    ("docker-", "docker"),
    ("containerd-", "containerd"),
    ("crio-", "cri-o"),
    ("libpod-", "podman"),
    ("podman-", "podman"),
];

fn parse_container_id(path: &str) -> Option<(Option<String>, String)> {
    // Two-pass parser. The first pass requires a known runtime prefix. This
    // is what stops Kubernetes pod IDs from being mistaken for container IDs:
    // a path like
    //   /kubepods.slice/.../kubepods-burstable-pod<uuid>.slice/cri-containerd-<id>.scope
    // contains both a pod UUID segment (hex-ish after `pod`) and the real
    // container scope segment. The first hex-only match was the pod, which
    // grouped every sidecar in the pod under one bogus "container".
    for segment in path.split('/') {
        let trimmed = strip_segment_suffixes(segment.trim());
        for (prefix, runtime) in RUNTIME_PREFIXES {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                if is_container_id(rest) {
                    return Some((Some((*runtime).to_string()), rest.to_string()));
                }
            }
        }
    }

    // Fallback: a bare hex segment with no known prefix. Covers older
    // /docker/<id> layouts and unrecognised runtimes. Best-effort runtime
    // inference from the surrounding path; never override with kubepods-
    // because in k8s the unprefixed hex is almost always a pod UUID, not a
    // container id, and we'd rather report runtime=None than mislabel.
    for segment in path.split('/') {
        let trimmed = strip_segment_suffixes(segment.trim());
        if is_container_id(trimmed) {
            let runtime = if path.contains("kubepods") {
                None
            } else if path.contains("/docker") {
                Some("docker".to_string())
            } else if path.contains("containerd") {
                Some("containerd".to_string())
            } else if path.contains("crio") {
                Some("cri-o".to_string())
            } else {
                None
            };
            return Some((runtime, trimmed.to_string()));
        }
    }

    None
}

fn strip_segment_suffixes(segment: &str) -> &str {
    segment
        .trim_end_matches(".scope")
        .trim_end_matches(".service")
        .trim_end_matches(".slice")
}

fn is_container_id(value: &str) -> bool {
    value.len() >= 12 && value.chars().all(|char| char.is_ascii_hexdigit())
}

fn read_namespaces(pid: u32) -> NamespaceInfo {
    NamespaceInfo {
        pid: read_namespace_link(pid, "pid"),
        mnt: read_namespace_link(pid, "mnt"),
        net: read_namespace_link(pid, "net"),
        user: read_namespace_link(pid, "user"),
    }
}

fn namespace_risk(namespaces: &NamespaceInfo, host: &NamespaceInfo) -> NamespaceRisk {
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

fn read_mount_risk(pid: u32) -> MountRisk {
    let mountinfo = fs::read_to_string(format!("/proc/{pid}/mountinfo")).unwrap_or_default();
    parse_mount_risk(&mountinfo)
}

fn parse_mount_risk(mountinfo: &str) -> MountRisk {
    let mut risk = MountRisk::default();

    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let fields = left.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 6 {
            continue;
        }

        let mount_point = decode_mountinfo_path(fields[4]);
        let options = fields[5];
        let source = right.split_whitespace().nth(1).unwrap_or("");
        let writable = options.split(',').any(|option| option == "rw");

        if mount_point == "/host" || mount_point == "/rootfs" || source == "/" {
            risk.host_root_mounted = true;
            risk.suspicious_mounts
                .push(format!("{source} -> {mount_point}"));
        }
        if is_docker_socket(mount_point.as_str()) || is_docker_socket(source) {
            risk.docker_socket_mounted = true;
            risk.suspicious_mounts
                .push(format!("{source} -> {mount_point}"));
        }
        if mount_point == "/proc" && writable {
            risk.proc_mounted_rw = true;
        }
        if mount_point == "/sys" && writable {
            risk.sys_mounted_rw = true;
        }
    }

    risk.suspicious_mounts.sort();
    risk.suspicious_mounts.dedup();
    risk
}

fn decode_mountinfo_path(path: &str) -> String {
    path.replace("\\040", " ")
}

fn is_docker_socket(path: &str) -> bool {
    path == "docker.sock" || path.ends_with("/docker.sock")
}

fn inspect_runtime_config(runtime: Option<&str>, container_id: &str) -> RuntimeConfig {
    match runtime {
        Some("docker") => inspect_docker_config(container_id),
        _ => RuntimeConfig::default(),
    }
}

fn inspect_docker_config(container_id: &str) -> RuntimeConfig {
    let output = std::process::Command::new("docker")
        .args(["inspect", container_id])
        .output();

    let Ok(output) = output else {
        return RuntimeConfig::default();
    };
    if !output.status.success() {
        return RuntimeConfig::default();
    }

    let text = String::from_utf8_lossy(&output.stdout);
    RuntimeConfig {
        privileged: json_bool_field(&text, "Privileged"),
        seccomp_profile: docker_seccomp_profile(&text),
        configured_capabilities: docker_cap_add(&text),
        host_pid: json_string_field(&text, "PidMode").map(|value| value == "host"),
        host_network: json_string_field(&text, "NetworkMode").map(|value| value == "host"),
        host_ipc: json_string_field(&text, "IpcMode").map(|value| value == "host"),
        source: Some("docker inspect".to_string()),
    }
}

fn json_bool_field(text: &str, field: &str) -> Option<bool> {
    let needle = format!("\"{field}\":");
    let value = text.split(&needle).nth(1)?.trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":");
    let value = text.split(&needle).nth(1)?.trim_start();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    Some(value[..end].to_string())
}

fn docker_seccomp_profile(text: &str) -> Option<String> {
    if text.contains("\"seccomp=unconfined\"") {
        return Some("unconfined".to_string());
    }
    if text.contains("\"SecurityOpt\": null") {
        return Some("default".to_string());
    }
    None
}

fn docker_cap_add(text: &str) -> Vec<String> {
    let Some(section) = text.split("\"CapAdd\":").nth(1) else {
        return Vec::new();
    };
    let Some(section) = section.split(']').next() else {
        return Vec::new();
    };
    section
        .split('"')
        .enumerate()
        .filter_map(|(index, value)| (index % 2 == 1).then_some(value.to_string()))
        .collect()
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

// Reads field 22 (starttime, in clock ticks since boot) from /proc/<pid>/stat.
// Used as a stable per-process identity token to detect pid reuse across
// cache lifetimes.
fn read_process_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat_starttime(&stat)
}

// The comm field (#2) can contain spaces and parens, so we anchor parsing on
// the LAST ')' before splitting the rest on whitespace.
fn parse_proc_stat_starttime(stat: &str) -> Option<u64> {
    let last_paren = stat.rfind(')')?;
    let after = stat.get(last_paren + 1..)?;
    // After ')', fields are state(0), ppid(1), ..., starttime is field 22
    // overall, which is index 22 - 3 = 19 in the post-comm slice.
    after.split_whitespace().nth(19)?.parse::<u64>().ok()
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
    fn parses_libpod_cgroup_id() {
        // libpod-<id>.scope was previously missed entirely because the
        // libpod- prefix was not stripped, leaving "libpod-<id>" which has
        // hyphens and is not all-hex.
        let id = "abc123def4567890abc123def4567890abc123def4567890abc123def456deadbeef";
        let path = format!("/machine.slice/libpod-{id}.scope");

        let parsed = parse_container_id(&path);

        assert_eq!(parsed, Some((Some("podman".to_string()), id.to_string())));
    }

    #[test]
    fn parses_k8s_systemd_driver_picks_container_not_pod_uuid() {
        // Real-world layout: the pod segment has a hex-rich UUID (with
        // underscores in the systemd cgroupdriver). Make sure we don't pick
        // it up as the container ID — that bug would collapse all sidecars
        // in a pod under a single fake "container".
        let pod_uuid = "1234abcd_5678_90ef_1234_567890abcdef";
        let container_id = "deadbeef0123deadbeef0123deadbeef0123deadbeef0123";
        let path = format!(
            "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod{pod_uuid}.slice/cri-containerd-{container_id}.scope"
        );

        let parsed = parse_container_id(&path);

        assert_eq!(
            parsed,
            Some((Some("containerd".to_string()), container_id.to_string()))
        );
    }

    #[test]
    fn prefers_prefixed_segment_over_bare_hex_segment() {
        // Defensive: even if some segment ahead of the runtime-prefixed one
        // happened to be all hex (e.g. a hashed parent slice), prefer the
        // prefixed scope. This is the property that prevents pod-vs-container
        // confusion in less common layouts.
        let bare_hex = "0123456789abcdef0123456789abcdef";
        let container_id = "deadbeefdeadbeefdeadbeefdeadbeef";
        let path = format!("/parent/{bare_hex}/cri-containerd-{container_id}.scope");

        let parsed = parse_container_id(&path);

        assert_eq!(
            parsed,
            Some((Some("containerd".to_string()), container_id.to_string()))
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
    fn parses_starttime_with_simple_comm() {
        // Synthetic /proc/<pid>/stat line: pid=1234, comm=(bash), state=S,
        // followed by 19 dummy fields and starttime=987654321.
        let stat = "1234 (bash) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 987654321 8192 100 18446744073709551615 1 1 0 0 0 0";

        assert_eq!(parse_proc_stat_starttime(stat), Some(987654321));
    }

    #[test]
    fn parses_starttime_with_parens_in_comm() {
        // comm field contains spaces and nested parens; rfind(')') is what
        // keeps the parser correct in this case.
        let stat = "4242 (my (weird) proc) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 555 0 0 0 0 0";

        assert_eq!(parse_proc_stat_starttime(stat), Some(555));
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

    #[test]
    fn parses_mount_risk_signals() {
        let mountinfo = "1 2 0:1 / / rw - ext4 / rw\n2 1 0:2 /docker.sock /var/run/docker.sock rw - bind /var/run/docker.sock rw\n3 1 0:3 / /sys rw - sysfs sysfs rw\n";

        let risk = parse_mount_risk(mountinfo);

        assert!(risk.host_root_mounted);
        assert!(risk.docker_socket_mounted);
        assert!(risk.sys_mounted_rw);
    }

    #[test]
    fn does_not_flag_lookalike_docker_sock_paths() {
        let mountinfo = "1 2 0:1 / /var/lib/notdocker.sock.d rw - tmpfs tmpfs rw\n";

        let risk = parse_mount_risk(mountinfo);

        assert!(!risk.docker_socket_mounted);
    }

    #[test]
    fn flags_docker_sock_at_alternate_paths() {
        let mountinfo = "1 2 0:1 /docker.sock /run/docker.sock rw - bind /run/docker.sock rw\n";

        let risk = parse_mount_risk(mountinfo);

        assert!(risk.docker_socket_mounted);
    }

    #[test]
    fn parses_docker_inspect_fragments() {
        let text = r#""Privileged": true, "PidMode": "host", "NetworkMode": "bridge", "SecurityOpt": ["seccomp=unconfined"], "CapAdd": ["SYS_ADMIN", "NET_ADMIN"]"#;

        assert_eq!(json_bool_field(text, "Privileged"), Some(true));
        assert_eq!(json_string_field(text, "PidMode"), Some("host".to_string()));
        assert_eq!(docker_seccomp_profile(text), Some("unconfined".to_string()));
        assert_eq!(
            docker_cap_add(text),
            vec!["SYS_ADMIN".to_string(), "NET_ADMIN".to_string()]
        );
    }
}
