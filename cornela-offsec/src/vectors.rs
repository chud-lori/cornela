// Container/host escape vectors with applicability checks.
//
// Each vector evaluates the recon result and returns:
//   - applicable=true  : every prerequisite is satisfied; the technique is
//                        actionable from the current context.
//   - applicable=false : prerequisites are not met. Reasons explain why.
//
// We do NOT execute any of these. The output is a triage list for an
// authorized red-teamer to drive next steps with their own kit.

use crate::recon::{
    self, ReconResult, CAP_DAC_READ_SEARCH, CAP_NET_ADMIN, CAP_SYS_ADMIN, CAP_SYS_BOOT,
    CAP_SYS_MODULE, CAP_SYS_PTRACE, CAP_SYS_RAWIO,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    // Reserved for future categorization (informational findings, low-impact
    // signals). Kept here so JSON consumers see a stable severity vocabulary.
    #[allow(dead_code)]
    Info,
    #[allow(dead_code)]
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VectorEval {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub severity_if_exploited: Severity,
    pub applicable: bool,
    pub reasons: Vec<String>,
    pub manual_trigger: &'static str,
    pub reference: &'static str,
}

pub fn evaluate_all(recon: &ReconResult) -> Vec<VectorEval> {
    vec![
        cgroup_v1_release_agent(recon),
        docker_socket_rce(recon),
        containerd_socket_rce(recon),
        kubelet_api_abuse(recon),
        host_root_chroot(recon),
        proc_kcore_disclosure(recon),
        ptrace_host_processes(recon),
        cap_sys_module_load(recon),
        cap_dac_read_search_handle_traversal(recon),
        host_net_with_cap_net_admin(recon),
        unconfined_lsm_seccomp(recon),
        copy_fail_kernel(recon),
        k8s_service_account_token(recon),
        kernel_debug_mounted(recon),
        sys_writable(recon),
    ]
}

fn cgroup_v1_release_agent(recon: &ReconResult) -> VectorEval {
    let mut reasons = Vec::new();
    let has_admin = recon::has_cap(recon.capabilities.effective, CAP_SYS_ADMIN);
    let cgroup_v1_writable = recon
        .mounts
        .cgroupfs_writable_paths
        .iter()
        .any(|p| !p.contains("cgroup2"));

    if !has_admin {
        reasons.push("missing CAP_SYS_ADMIN (effective)".to_string());
    }
    if !cgroup_v1_writable {
        reasons.push("no writable cgroup-v1 mount detected".to_string());
    }
    if reasons.is_empty() {
        reasons.push(format!(
            "CAP_SYS_ADMIN held and writable cgroup-v1 mount(s) exist: {}",
            recon.mounts.cgroupfs_writable_paths.join(", ")
        ));
    }

    VectorEval {
        id: "cgroup_v1_release_agent",
        name: "cgroup-v1 release_agent host command execution",
        category: "container_escape",
        severity_if_exploited: Severity::Critical,
        applicable: has_admin && cgroup_v1_writable,
        reasons,
        manual_trigger: "mount a child cgroup, set notify_on_release=1, write a payload path to release_agent, populate the cgroup with a process that exits.",
        reference: "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
    }
}

fn docker_socket_rce(recon: &ReconResult) -> VectorEval {
    let location = recon.mounts.docker_socket.clone();
    let applicable = location.is_some();
    let reasons = match &location {
        Some(loc) => vec![format!("docker.sock mounted: {loc}")],
        None => vec!["docker.sock not visible in this mount namespace".to_string()],
    };
    VectorEval {
        id: "docker_socket_rce",
        name: "Docker socket → privileged container → host RCE",
        category: "runtime_breakout",
        severity_if_exploited: Severity::Critical,
        applicable,
        reasons,
        manual_trigger: "use a docker client (or curl --unix-socket) against the socket to launch a new container with --privileged --pid=host -v /:/host and chroot.",
        reference: "https://docs.docker.com/engine/security/protect-access/",
    }
}

fn containerd_socket_rce(recon: &ReconResult) -> VectorEval {
    let location = recon.mounts.containerd_socket.clone();
    let applicable = location.is_some();
    let reasons = match &location {
        Some(loc) => vec![format!("containerd.sock mounted: {loc}")],
        None => vec!["containerd.sock not visible in this mount namespace".to_string()],
    };
    VectorEval {
        id: "containerd_socket_rce",
        name: "containerd socket → host RCE via ctr/crictl",
        category: "runtime_breakout",
        severity_if_exploited: Severity::Critical,
        applicable,
        reasons,
        manual_trigger: "ctr --address <sock> run --privileged --mount type=bind,src=/,dst=/host ... or use the gRPC API directly.",
        reference: "https://github.com/containerd/containerd/blob/main/docs/getting-started.md",
    }
}

fn kubelet_api_abuse(recon: &ReconResult) -> VectorEval {
    let mut reasons = Vec::new();
    let mut applicable = false;

    if let Some(loc) = &recon.mounts.kubelet_socket {
        applicable = true;
        reasons.push(format!("kubelet socket mounted: {loc}"));
    }
    if recon.kubernetes.service_account_token_present {
        applicable = true;
        reasons.push("Kubernetes service account token present".to_string());
        if let Some(host) = &recon.kubernetes.api_server_env {
            let port = recon
                .kubernetes
                .api_server_port_env
                .as_deref()
                .unwrap_or("443");
            reasons.push(format!("API server reachable at {host}:{port}"));
        }
    }
    if !applicable {
        reasons.push("no kubelet socket and no SA token present".to_string());
    }

    VectorEval {
        id: "kubelet_api_abuse",
        name: "Kubelet/API abuse via mounted socket or SA token",
        category: "kubernetes",
        severity_if_exploited: Severity::High,
        applicable,
        reasons,
        manual_trigger: "with the SA token: curl -k -H 'Authorization: Bearer $(cat token)' https://$KUBERNETES_SERVICE_HOST/api/v1/namespaces — then enumerate RBAC and pod-exec rights.",
        reference: "https://kubernetes.io/docs/reference/access-authn-authz/",
    }
}

fn host_root_chroot(recon: &ReconResult) -> VectorEval {
    let location = recon.mounts.host_root_mounted.clone();
    let applicable = location.is_some();
    let reasons = match &location {
        Some(loc) => vec![format!("host root visible: {loc}")],
        None => vec!["host root filesystem not mounted into this container".to_string()],
    };
    VectorEval {
        id: "host_root_mount",
        name: "Host root filesystem mounted → chroot escape",
        category: "container_escape",
        severity_if_exploited: Severity::Critical,
        applicable,
        reasons,
        manual_trigger: "chroot into the host mount and exec a shell. With write access, schedule cron/systemd payloads on the host.",
        reference: "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mount",
    }
}

fn proc_kcore_disclosure(recon: &ReconResult) -> VectorEval {
    let kcore_readable = recon.kernel.kcore_readable
        && (recon::has_cap(recon.capabilities.effective, CAP_SYS_RAWIO) || recon.uid == Some(0));
    let mut reasons = Vec::new();
    if !recon.kernel.kcore_readable {
        reasons.push("/proc/kcore not present or not opened".to_string());
    } else if recon.uid != Some(0) && !recon::has_cap(recon.capabilities.effective, CAP_SYS_RAWIO) {
        reasons.push("/proc/kcore visible but reads require uid 0 or CAP_SYS_RAWIO".to_string());
    } else {
        reasons.push("/proc/kcore openable — kernel memory disclosure primitive".to_string());
    }
    if recon.kernel.kallsyms_readable {
        reasons.push(
            "/proc/kallsyms exposes real kernel pointers (kptr_restrict relaxed)".to_string(),
        );
    }
    VectorEval {
        id: "proc_kcore_disclosure",
        name: "/proc/kcore + /proc/kallsyms kernel disclosure",
        category: "kernel_disclosure",
        severity_if_exploited: Severity::High,
        applicable: kcore_readable,
        reasons,
        manual_trigger: "read /proc/kcore at offsets resolved from /proc/kallsyms to leak kernel data. Useful for KASLR bypass and credential structure scraping.",
        reference: "https://man7.org/linux/man-pages/man5/proc.5.html",
    }
}

fn ptrace_host_processes(recon: &ReconResult) -> VectorEval {
    let host_pid = recon.namespaces.host_pid;
    let cap = recon::has_cap(recon.capabilities.effective, CAP_SYS_PTRACE);
    let mut reasons = Vec::new();
    if !host_pid {
        reasons.push("not in host PID namespace".to_string());
    }
    if !cap {
        reasons.push("missing CAP_SYS_PTRACE (effective)".to_string());
    }
    if reasons.is_empty() {
        reasons.push(
            "host PID namespace AND CAP_SYS_PTRACE held — can attach to host pid 1".to_string(),
        );
    }
    VectorEval {
        id: "ptrace_host",
        name: "ptrace host processes (CAP_SYS_PTRACE + host PID ns)",
        category: "container_escape",
        severity_if_exploited: Severity::High,
        applicable: host_pid && cap,
        reasons,
        manual_trigger:
            "PTRACE_ATTACH a host process (e.g. pid 1) and inject shellcode or read its memory.",
        reference: "https://man7.org/linux/man-pages/man2/ptrace.2.html",
    }
}

fn cap_sys_module_load(recon: &ReconResult) -> VectorEval {
    let cap = recon::has_cap(recon.capabilities.effective, CAP_SYS_MODULE);
    let reasons = if cap {
        vec!["CAP_SYS_MODULE held — can init_module() arbitrary kernel code".to_string()]
    } else {
        vec!["missing CAP_SYS_MODULE".to_string()]
    };
    VectorEval {
        id: "cap_sys_module",
        name: "Load arbitrary kernel module (CAP_SYS_MODULE)",
        category: "kernel_compromise",
        severity_if_exploited: Severity::Critical,
        applicable: cap,
        reasons,
        manual_trigger: "build a minimal .ko with a host-side payload, then init_module() it. Runs in ring 0, full host compromise.",
        reference: "https://man7.org/linux/man-pages/man2/init_module.2.html",
    }
}

fn cap_dac_read_search_handle_traversal(recon: &ReconResult) -> VectorEval {
    let cap = recon::has_cap(recon.capabilities.effective, CAP_DAC_READ_SEARCH);
    let reasons = if cap {
        vec![
            "CAP_DAC_READ_SEARCH held — Shocker-style open_by_handle_at host traversal possible"
                .to_string(),
        ]
    } else {
        vec!["missing CAP_DAC_READ_SEARCH".to_string()]
    };
    VectorEval {
        id: "shocker_open_by_handle",
        name: "open_by_handle_at host filesystem traversal (Shocker)",
        category: "container_escape",
        severity_if_exploited: Severity::High,
        applicable: cap,
        reasons,
        manual_trigger: "brute-force file_handle values via open_by_handle_at(2) to read host /etc/shadow and similar.",
        reference: "https://stealth.openwall.net/xSports/shocker.c",
    }
}

fn host_net_with_cap_net_admin(recon: &ReconResult) -> VectorEval {
    let host_net = recon.namespaces.host_net;
    let cap = recon::has_cap(recon.capabilities.effective, CAP_NET_ADMIN);
    let mut reasons = Vec::new();
    if !host_net {
        reasons.push("not sharing host network namespace".to_string());
    }
    if !cap {
        reasons.push("missing CAP_NET_ADMIN".to_string());
    }
    if reasons.is_empty() {
        reasons.push(
            "host network ns + CAP_NET_ADMIN — sniff/MITM and iptables manipulation".to_string(),
        );
    }
    VectorEval {
        id: "host_net_admin",
        name: "Host network namespace abuse (sniff/MITM/firewall)",
        category: "lateral_movement",
        severity_if_exploited: Severity::High,
        applicable: host_net && cap,
        reasons,
        manual_trigger: "tcpdump on host interfaces; rewrite iptables to redirect host traffic; ARP-spoof other workloads.",
        reference: "https://man7.org/linux/man-pages/man7/capabilities.7.html",
    }
}

fn unconfined_lsm_seccomp(recon: &ReconResult) -> VectorEval {
    let seccomp_off = matches!(recon.security.seccomp_mode, Some(0) | None);
    let apparmor_off =
        recon.security.apparmor_unconfined || recon.security.apparmor_profile.is_none();
    let nnp_off = !recon.security.no_new_privs.unwrap_or(false);
    let mut reasons = Vec::new();
    if seccomp_off {
        reasons.push("seccomp disabled or mode=0".to_string());
    }
    if apparmor_off {
        reasons.push("AppArmor unconfined or no profile loaded".to_string());
    }
    if nnp_off {
        reasons.push("NoNewPrivs not set".to_string());
    }
    if reasons.is_empty() {
        reasons.push("seccomp + LSM + NNP all enforced".to_string());
    }
    VectorEval {
        id: "unconfined_lsm",
        name: "Unconfined LSM/seccomp profile broadens the syscall surface",
        category: "weak_isolation",
        severity_if_exploited: Severity::Medium,
        applicable: seccomp_off && apparmor_off,
        reasons,
        manual_trigger: "syscalls normally blocked by the default profile (mount, ptrace, bpf, userfaultfd, keyctl) are reachable — combine with capability findings.",
        reference: "https://docs.docker.com/engine/security/seccomp/",
    }
}

fn copy_fail_kernel(recon: &ReconResult) -> VectorEval {
    let in_range = recon
        .kernel
        .release
        .as_deref()
        .map(is_kernel_in_copy_fail_range)
        .unwrap_or(false);
    let surface = recon.kernel.algif_aead_loaded || recon.kernel.af_alg_available;
    let mut reasons = Vec::new();
    if !in_range {
        reasons.push(format!(
            "kernel {} not in known Copy Fail vulnerable range",
            recon.kernel.release.as_deref().unwrap_or("?")
        ));
    }
    if !surface {
        reasons.push("AF_ALG / algif_aead surface not exposed".to_string());
    }
    if reasons.is_empty() {
        reasons.push("kernel in Copy Fail range AND AF_ALG/algif_aead exposed".to_string());
    }
    VectorEval {
        id: "cve_2026_31431_copy_fail",
        name: "CVE-2026-31431 Copy Fail (AF_ALG + splice)",
        category: "kernel_cve",
        severity_if_exploited: Severity::Critical,
        applicable: in_range && surface,
        reasons,
        manual_trigger: "use a vetted PoC from your red-team kit; cornela-offsec does not ship kernel exploits. See the Theori reference implementation for an authorized lab run.",
        reference: "https://github.com/theori-io/copy-fail-CVE-2026-31431",
    }
}

fn k8s_service_account_token(recon: &ReconResult) -> VectorEval {
    let present = recon.kubernetes.service_account_token_present;
    let mut reasons = Vec::new();
    if present {
        reasons.push("service account token mounted at default path".to_string());
        if let Some(ns) = &recon.kubernetes.service_account_namespace {
            reasons.push(format!("namespace: {ns}"));
        }
    } else {
        reasons.push("no service account token at default path".to_string());
    }
    VectorEval {
        id: "k8s_sa_token",
        name: "Kubernetes service account token recon",
        category: "kubernetes",
        severity_if_exploited: Severity::High,
        applicable: present,
        reasons,
        manual_trigger: "run kubectl auth can-i --list with the token; enumerate secrets, exec into pods, or use a privileged role.",
        reference: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/",
    }
}

fn kernel_debug_mounted(recon: &ReconResult) -> VectorEval {
    let mounted = recon.mounts.kernel_debug_mounted;
    let reasons = if mounted {
        vec!["/sys/kernel/debug exposed inside container".to_string()]
    } else {
        vec!["/sys/kernel/debug not exposed".to_string()]
    };
    VectorEval {
        id: "debugfs_exposed",
        name: "debugfs exposed inside container",
        category: "weak_isolation",
        severity_if_exploited: Severity::High,
        applicable: mounted,
        reasons,
        manual_trigger: "read /sys/kernel/debug/* for kernel internals; some entries are writable and accept commands that affect the host.",
        reference: "https://docs.kernel.org/filesystems/debugfs.html",
    }
}

fn sys_writable(recon: &ReconResult) -> VectorEval {
    let writable = recon.mounts.sys_writable;
    let reasons = if writable {
        vec!["/sys mounted read-write — cgroup/uevent/module_load attack surface".to_string()]
    } else {
        vec!["/sys is read-only or not mounted".to_string()]
    };
    let _ = (CAP_SYS_BOOT,); // referenced for future variants
    VectorEval {
        id: "sysfs_rw",
        name: "/sys mounted read-write",
        category: "weak_isolation",
        severity_if_exploited: Severity::High,
        applicable: writable,
        reasons,
        manual_trigger: "writable sysfs enables uevent helpers, modprobe paths, and (with CAP_SYS_ADMIN) several escape primitives.",
        reference: "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mount",
    }
}

// Conservative kernel range check for CVE-2026-31431 "Copy Fail". Returns
// true for kernels that are within the publicly reported affected window
// and false outside it. This is a triage signal, not a definitive answer —
// distros may have backported the fix without bumping the major.minor.
fn is_kernel_in_copy_fail_range(release: &str) -> bool {
    let Some((major, minor, patch)) = parse_kernel_release(release) else {
        return false;
    };
    // Public reporting placed the vulnerable window roughly at 6.0..=6.10
    // upstream. Older 5.x without the affected algif_aead splice path is
    // not in scope. Adjust as the public timeline solidifies.
    if major != 6 {
        return false;
    }
    let _ = patch;
    minor <= 10
}

fn parse_kernel_release(release: &str) -> Option<(u64, u64, u64)> {
    let core = release.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts
        .next()
        .and_then(|p| p.parse::<u64>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::{
        Capabilities, KernelSurface, KubernetesContext, MountFindings, Namespaces, SecurityProfile,
    };

    fn empty_recon() -> ReconResult {
        ReconResult {
            uid: Some(0),
            gid: Some(0),
            pid: 1,
            comm: None,
            command_line: None,
            capabilities: Capabilities::default(),
            security: SecurityProfile::default(),
            namespaces: Namespaces::default(),
            mounts: MountFindings::default(),
            kernel: KernelSurface::default(),
            container: Default::default(),
            kubernetes: KubernetesContext::default(),
        }
    }

    #[test]
    fn release_agent_requires_admin_and_writable_cgroup() {
        let mut recon = empty_recon();
        let result = cgroup_v1_release_agent(&recon);
        assert!(!result.applicable);

        recon.capabilities.effective = Some(1u64 << CAP_SYS_ADMIN);
        recon
            .mounts
            .cgroupfs_writable_paths
            .push("/sys/fs/cgroup/memory".to_string());
        let result = cgroup_v1_release_agent(&recon);
        assert!(result.applicable);
        assert_eq!(result.severity_if_exploited, Severity::Critical);
    }

    #[test]
    fn docker_socket_present_makes_vector_applicable() {
        let mut recon = empty_recon();
        recon.mounts.docker_socket = Some("/var/run/docker.sock -> /var/run/docker.sock".into());
        let result = docker_socket_rce(&recon);
        assert!(result.applicable);
    }

    #[test]
    fn copy_fail_requires_both_kernel_and_surface() {
        let mut recon = empty_recon();
        recon.kernel.release = Some("6.5.0-1-amd64".to_string());
        let result = copy_fail_kernel(&recon);
        assert!(!result.applicable, "no AF_ALG surface yet");

        recon.kernel.algif_aead_loaded = true;
        let result = copy_fail_kernel(&recon);
        assert!(result.applicable);
    }

    #[test]
    fn copy_fail_skips_old_kernels() {
        assert!(!is_kernel_in_copy_fail_range("4.19.0"));
        assert!(!is_kernel_in_copy_fail_range("5.10.220"));
        assert!(is_kernel_in_copy_fail_range("6.5.0-generic"));
        assert!(!is_kernel_in_copy_fail_range("6.20.0"));
        assert!(!is_kernel_in_copy_fail_range("garbage"));
    }

    #[test]
    fn evaluate_all_returns_full_set() {
        let result = evaluate_all(&empty_recon());
        assert_eq!(result.len(), 15);
    }
}
