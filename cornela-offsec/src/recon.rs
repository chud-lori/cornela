// Attacker-perspective enumeration of the current process's container/host
// surface. Read-only. Does not call any escape primitive.

use std::env;
use std::fs;
use std::path::Path;

use crate::proc;

#[derive(Debug, Clone, Default)]
pub struct ReconResult {
    pub uid: Option<u64>,
    pub gid: Option<u64>,
    pub pid: u32,
    pub comm: Option<String>,
    pub command_line: Option<String>,
    pub capabilities: Capabilities,
    pub security: SecurityProfile,
    pub namespaces: Namespaces,
    pub mounts: MountFindings,
    pub kernel: KernelSurface,
    pub container: ContainerContext,
    pub kubernetes: KubernetesContext,
}

#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    pub effective: Option<u64>,
    pub permitted: Option<u64>,
    pub bounding: Option<u64>,
    pub inheritable: Option<u64>,
    pub ambient: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct SecurityProfile {
    pub seccomp_mode: Option<u8>,
    pub no_new_privs: Option<bool>,
    pub apparmor_profile: Option<String>,
    pub apparmor_unconfined: bool,
    pub selinux_context: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Namespaces {
    pub pid: Option<String>,
    pub mnt: Option<String>,
    pub net: Option<String>,
    pub user: Option<String>,
    pub uts: Option<String>,
    pub ipc: Option<String>,
    pub host_pid: bool,
    pub host_mnt: bool,
    pub host_net: bool,
    pub host_user: bool,
    pub host_ipc: bool,
}

#[derive(Debug, Clone, Default)]
pub struct MountFindings {
    pub host_root_mounted: Option<String>,
    pub docker_socket: Option<String>,
    pub containerd_socket: Option<String>,
    pub crio_socket: Option<String>,
    pub kubelet_socket: Option<String>,
    pub proc_writable: bool,
    pub sys_writable: bool,
    pub cgroupfs_writable_paths: Vec<String>,
    pub kernel_debug_mounted: bool,
    pub other_suspicious: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct KernelSurface {
    pub release: Option<String>,
    pub algif_aead_loaded: bool,
    pub af_alg_available: bool,
    pub kcore_readable: bool,
    pub kallsyms_readable: bool,
    pub modules_loaded: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ContainerContext {
    pub in_container: bool,
    pub runtime_hint: Option<String>,
    pub cgroup_path: Option<String>,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct KubernetesContext {
    pub service_account_token_present: bool,
    pub service_account_namespace: Option<String>,
    pub api_server_env: Option<String>,
    pub api_server_port_env: Option<String>,
    pub kubelet_dns_in_resolv: bool,
}

pub fn collect() -> ReconResult {
    let status = proc::read_self_status();
    let pid = std::process::id();

    let capabilities = Capabilities {
        effective: proc::parse_cap_hex(&status, "CapEff:"),
        permitted: proc::parse_cap_hex(&status, "CapPrm:"),
        bounding: proc::parse_cap_hex(&status, "CapBnd:"),
        inheritable: proc::parse_cap_hex(&status, "CapInh:"),
        ambient: proc::parse_cap_hex(&status, "CapAmb:"),
    };

    let security = SecurityProfile {
        seccomp_mode: proc::status_u8(&status, "Seccomp:"),
        no_new_privs: proc::status_u8(&status, "NoNewPrivs:").map(|value| value != 0),
        apparmor_profile: read_apparmor_profile(),
        apparmor_unconfined: read_apparmor_profile()
            .map(|profile| profile == "unconfined")
            .unwrap_or(false),
        selinux_context: read_selinux_context(),
    };

    let namespaces = collect_namespaces(pid);
    let mounts = collect_mounts();
    let kernel = collect_kernel();
    let container = detect_container_context();
    let kubernetes = collect_k8s();

    ReconResult {
        uid: proc::status_first_u64(&status, "Uid:"),
        gid: proc::status_first_u64(&status, "Gid:"),
        pid,
        comm: proc::status_string(&status, "Name:"),
        command_line: proc::read_self_cmdline(),
        capabilities,
        security,
        namespaces,
        mounts,
        kernel,
        container,
        kubernetes,
    }
}

fn collect_namespaces(pid: u32) -> Namespaces {
    let me = read_ns_set(pid);
    let host = read_ns_set(1);
    Namespaces {
        host_pid: me.pid.is_some() && me.pid == host.pid,
        host_mnt: me.mnt.is_some() && me.mnt == host.mnt,
        host_net: me.net.is_some() && me.net == host.net,
        host_user: me.user.is_some() && me.user == host.user,
        host_ipc: me.ipc.is_some() && me.ipc == host.ipc,
        pid: me.pid,
        mnt: me.mnt,
        net: me.net,
        user: me.user,
        uts: me.uts,
        ipc: me.ipc,
    }
}

fn read_ns_set(pid: u32) -> Namespaces {
    Namespaces {
        pid: proc::read_namespace_link(pid, "pid"),
        mnt: proc::read_namespace_link(pid, "mnt"),
        net: proc::read_namespace_link(pid, "net"),
        user: proc::read_namespace_link(pid, "user"),
        uts: proc::read_namespace_link(pid, "uts"),
        ipc: proc::read_namespace_link(pid, "ipc"),
        ..Namespaces::default()
    }
}

fn collect_mounts() -> MountFindings {
    let text = proc::read_self_mountinfo();
    let entries = proc::parse_mountinfo(&text);
    let mut out = MountFindings::default();

    for entry in &entries {
        let mp = entry.mount_point.as_str();
        let src = entry.source.as_str();
        let writable = entry.options.split(',').any(|opt| opt == "rw");

        // Host root: a container that mounts the host's filesystem under
        // /host or /rootfs, OR has the bind source "/" — chroot-and-pivot
        // gets you the box.
        if mp == "/host" || mp == "/rootfs" || src == "/" {
            out.host_root_mounted = Some(format!("{src} -> {mp}"));
        }

        // Runtime sockets: trivial RCE if writable.
        if is_path_basename(mp, "docker.sock") || is_path_basename(src, "docker.sock") {
            out.docker_socket = Some(format!("{src} -> {mp}"));
        }
        if is_path_basename(mp, "containerd.sock") || is_path_basename(src, "containerd.sock") {
            out.containerd_socket = Some(format!("{src} -> {mp}"));
        }
        if is_path_basename(mp, "crio.sock") || is_path_basename(src, "crio.sock") {
            out.crio_socket = Some(format!("{src} -> {mp}"));
        }
        if mp.contains("/kubelet") && entry.fstype == "unix" {
            out.kubelet_socket = Some(format!("{src} -> {mp}"));
        }
        if is_path_basename(mp, "kubelet.sock") || is_path_basename(src, "kubelet.sock") {
            out.kubelet_socket = Some(format!("{src} -> {mp}"));
        }

        if mp == "/proc" && writable {
            out.proc_writable = true;
        }
        if mp == "/sys" && writable {
            out.sys_writable = true;
        }

        // Cgroupfs writable: the path to release_agent / sub-cgroup creation
        // for cgroup-v1 escape. cgroup2 also matters for less direct escapes.
        if (entry.fstype == "cgroup" || entry.fstype == "cgroup2") && writable {
            out.cgroupfs_writable_paths.push(mp.to_string());
        }

        // /sys/kernel/debug exposed inside container is rare and powerful.
        if mp == "/sys/kernel/debug" || mp.starts_with("/sys/kernel/debug/") {
            out.kernel_debug_mounted = true;
        }

        // Generic suspicious mounts worth listing.
        if matches!(
            mp,
            "/dev" | "/dev/mem" | "/dev/kmem" | "/var/run/secrets/kubernetes.io/serviceaccount"
        ) {
            out.other_suspicious.push(format!("{src} -> {mp}"));
        }
    }

    out.cgroupfs_writable_paths.sort();
    out.cgroupfs_writable_paths.dedup();
    out.other_suspicious.sort();
    out.other_suspicious.dedup();
    out
}

fn is_path_basename(path: &str, basename: &str) -> bool {
    Path::new(path)
        .file_name()
        .is_some_and(|name| name == basename)
}

fn collect_kernel() -> KernelSurface {
    let modules = proc::read_loaded_modules();
    let algif_aead_loaded = modules.iter().any(|m| m == "algif_aead");
    KernelSurface {
        release: proc::read_kernel_release(),
        algif_aead_loaded,
        af_alg_available: Path::new("/proc/crypto").exists(),
        kcore_readable: file_readable("/proc/kcore"),
        kallsyms_readable: kallsyms_has_real_addresses(),
        modules_loaded: modules.len(),
    }
}

fn file_readable(path: &str) -> bool {
    fs::File::open(path).is_ok()
}

// /proc/kallsyms exists on most kernels but kptr_restrict typically zeros
// the addresses for unprivileged callers. "Readable" in the offsec sense
// means we get real kernel pointers — a real kernel KASLR leak primitive.
fn kallsyms_has_real_addresses() -> bool {
    let Ok(text) = fs::read_to_string("/proc/kallsyms") else {
        return false;
    };
    text.lines()
        .take(20)
        .filter_map(|line| line.split_whitespace().next())
        .any(|addr| addr != "0000000000000000" && !addr.chars().all(|c| c == '0'))
}

fn detect_container_context() -> ContainerContext {
    let cgroup = proc::read_self_cgroup();
    let mut hint = None;
    let mut id = None;
    let mut path = None;

    for line in cgroup.lines() {
        let Some((_, p)) = line.rsplit_once(':') else {
            continue;
        };
        path.get_or_insert_with(|| p.to_string());

        for segment in p.split('/') {
            let s = segment
                .trim_end_matches(".scope")
                .trim_end_matches(".slice");
            if let Some(rest) = s.strip_prefix("cri-containerd-") {
                if is_hex_id(rest) {
                    hint = Some("containerd".to_string());
                    id = Some(rest.to_string());
                }
            } else if let Some(rest) = s.strip_prefix("docker-") {
                if is_hex_id(rest) {
                    hint = Some("docker".to_string());
                    id = Some(rest.to_string());
                }
            } else if let Some(rest) = s.strip_prefix("crio-") {
                if is_hex_id(rest) {
                    hint = Some("cri-o".to_string());
                    id = Some(rest.to_string());
                }
            } else if let Some(rest) = s.strip_prefix("libpod-") {
                if is_hex_id(rest) {
                    hint = Some("podman".to_string());
                    id = Some(rest.to_string());
                }
            }
        }
    }

    // Fallback: /.dockerenv, /run/.containerenv, or unique cgroup signatures.
    let in_container = id.is_some()
        || Path::new("/.dockerenv").exists()
        || Path::new("/run/.containerenv").exists()
        || cgroup.contains("kubepods")
        || cgroup.contains("docker")
        || cgroup.contains("containerd");

    ContainerContext {
        in_container,
        runtime_hint: hint,
        cgroup_path: path,
        container_id: id,
    }
}

fn is_hex_id(value: &str) -> bool {
    value.len() >= 12 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn collect_k8s() -> KubernetesContext {
    let token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token";
    let ns_path = "/var/run/secrets/kubernetes.io/serviceaccount/namespace";
    let token_present = Path::new(token_path).exists();
    let namespace = fs::read_to_string(ns_path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let api_server_env = env::var("KUBERNETES_SERVICE_HOST").ok();
    let api_server_port_env = env::var("KUBERNETES_SERVICE_PORT").ok();

    let kubelet_dns_in_resolv = fs::read_to_string("/etc/resolv.conf")
        .map(|text| {
            text.lines()
                .any(|line| line.contains("svc.cluster.local") || line.contains("cluster.local"))
        })
        .unwrap_or(false);

    KubernetesContext {
        service_account_token_present: token_present,
        service_account_namespace: namespace,
        api_server_env,
        api_server_port_env,
        kubelet_dns_in_resolv,
    }
}

fn read_apparmor_profile() -> Option<String> {
    fs::read_to_string("/proc/self/attr/current")
        .ok()
        .map(|value| value.trim().trim_end_matches('\0').trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| {
            // Format is typically "profile (mode)" e.g. "docker-default (enforce)"
            // or just "unconfined".
            value
                .split_whitespace()
                .next()
                .unwrap_or(&value)
                .to_string()
        })
}

fn read_selinux_context() -> Option<String> {
    fs::read_to_string("/proc/self/attr/current")
        .ok()
        .map(|value| value.trim().trim_end_matches('\0').to_string())
        .filter(|value| {
            // SELinux contexts have the form user:role:type:level. AppArmor
            // labels do not contain colons. This is the conventional way to
            // distinguish without an extra syscall.
            value.contains(':')
        })
}

// Capability bit numbers — kept here so we can answer capability questions
// without a libc dep. From <linux/capability.h>.
pub const CAP_DAC_READ_SEARCH: u8 = 2;
pub const CAP_NET_ADMIN: u8 = 12;
pub const CAP_SYS_MODULE: u8 = 16;
pub const CAP_SYS_RAWIO: u8 = 17;
#[allow(dead_code)]
pub const CAP_SYS_CHROOT: u8 = 18;
pub const CAP_SYS_PTRACE: u8 = 19;
pub const CAP_SYS_ADMIN: u8 = 21;
pub const CAP_SYS_BOOT: u8 = 22;
#[allow(dead_code)]
pub const CAP_MAC_ADMIN: u8 = 33;

pub fn has_cap(mask: Option<u64>, bit: u8) -> bool {
    mask.is_some_and(|m| m & (1u64 << bit) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bits() {
        let caps = (1u64 << CAP_SYS_ADMIN) | (1u64 << CAP_NET_ADMIN);
        assert!(has_cap(Some(caps), CAP_SYS_ADMIN));
        assert!(has_cap(Some(caps), CAP_NET_ADMIN));
        assert!(!has_cap(Some(caps), CAP_SYS_MODULE));
        assert!(!has_cap(None, CAP_SYS_ADMIN));
    }

    #[test]
    fn detects_hex_container_ids() {
        assert!(is_hex_id("deadbeef0123deadbeef0123"));
        assert!(!is_hex_id("kubepods-pod"));
        assert!(!is_hex_id("short"));
    }

    #[test]
    fn detects_runtime_socket_basename() {
        assert!(is_path_basename("/var/run/docker.sock", "docker.sock"));
        assert!(is_path_basename(
            "/run/containerd/containerd.sock",
            "containerd.sock"
        ));
        // Lookalike paths must not match.
        assert!(!is_path_basename(
            "/var/lib/notdocker.sock.d",
            "docker.sock"
        ));
    }
}
