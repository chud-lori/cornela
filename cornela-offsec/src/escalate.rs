// Local privilege-escalation enumeration. Pulls together the classic
// linpeas / linenum / GTFOBins-style checks that a red-teamer wants to
// run on every box. Read-only — we never *try* to escalate, we just
// enumerate what's exploitable.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct EscalateReport {
    pub uid: Option<u32>,
    pub euid: Option<u32>,
    pub kernel_release: Option<String>,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub category: &'static str,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
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

pub fn enumerate() -> EscalateReport {
    let mut report = EscalateReport {
        uid: read_self_uid(),
        euid: read_self_euid(),
        kernel_release: read_kernel_release(),
        findings: Vec::new(),
    };

    if let Some(f) = check_dangerous_suid() {
        report.findings.push(f);
    }
    if let Some(f) = check_sudo_l() {
        report.findings.push(f);
    }
    if let Some(f) = check_writable_path() {
        report.findings.push(f);
    }
    if let Some(f) = check_writable_cron() {
        report.findings.push(f);
    }
    if let Some(f) = check_world_writable_systemd_units() {
        report.findings.push(f);
    }
    if let Some(f) = check_kernel_cve_window(report.kernel_release.as_deref()) {
        report.findings.push(f);
    }
    if let Some(f) = check_readable_secrets() {
        report.findings.push(f);
    }
    if let Some(f) = check_caps_on_binaries() {
        report.findings.push(f);
    }
    if let Some(f) = check_docker_group() {
        report.findings.push(f);
    }

    report
        .findings
        .sort_by_key(|f| std::cmp::Reverse(f.severity));
    report
}

// SUID/SGID binaries that map directly to root via well-known GTFOBins
// vectors. Only flag the high-impact ones; a host typically has dozens
// of harmless suid binaries.
const SUID_ROOT_BINARIES: &[&str] = &[
    "nmap", "vim", "find", "bash", "more", "less", "nano", "cp", "awk",
    "man", "wget", "perl", "python", "python3", "ruby", "tar", "zip",
    "openssl", "tcpdump", "git", "env", "ftp", "make", "gdb", "strace",
    "expect", "tee", "node", "php", "ssh", "rsync", "curl", "ed",
    "socat", "xxd", "vimdiff", "rvim", "view",
];

fn check_dangerous_suid() -> Option<Finding> {
    let common_paths = [
        "/usr/bin", "/bin", "/usr/local/bin", "/usr/sbin", "/sbin",
        "/usr/local/sbin",
    ];
    let mut hits = Vec::new();
    for dir in common_paths {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let mode = meta.permissions().mode();
            // Setuid bit (04000) AND owner is root (uid 0).
            if mode & 0o4000 == 0 || meta.uid() != 0 {
                continue;
            }
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            if SUID_ROOT_BINARIES.iter().any(|b| **b == name) {
                hits.push(format!("{} ({:o})", path.display(), mode & 0o7777));
            }
        }
    }
    if hits.is_empty() {
        return None;
    }
    hits.sort();
    hits.dedup();
    Some(Finding {
        id: "suid_to_root",
        title: "Dangerous SUID-root binaries (GTFOBins map to root shell)",
        severity: Severity::High,
        category: "privesc_local",
        details: hits,
    })
}

fn check_sudo_l() -> Option<Finding> {
    let output = Command::new("sudo").arg("-n").arg("-l").output().ok()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut details = Vec::new();
    let mut nopasswd = false;
    let mut all_commands = false;
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("NOPASSWD") {
            nopasswd = true;
            details.push(format!("rule: {trimmed}"));
        }
        if trimmed.contains("(ALL) ALL") || trimmed.contains("(ALL : ALL) ALL") {
            all_commands = true;
        }
    }
    if details.is_empty() && !all_commands {
        return None;
    }
    let severity = if nopasswd && all_commands {
        Severity::Critical
    } else if nopasswd || all_commands {
        Severity::High
    } else {
        Severity::Medium
    };
    if all_commands {
        details.push("user can run ALL commands as root".to_string());
    }
    Some(Finding {
        id: "sudo_l",
        title: "Permissive sudo rules (NOPASSWD or ALL)",
        severity,
        category: "privesc_local",
        details,
    })
}

fn check_writable_path() -> Option<Finding> {
    let paths = std::env::var_os("PATH")?;
    let mut details = Vec::new();
    for entry in std::env::split_paths(&paths) {
        let Ok(meta) = fs::metadata(&entry) else {
            continue;
        };
        let mode = meta.permissions().mode();
        // World-writable (002) without the sticky bit (01000) lets anyone
        // drop a malicious binary that the next privileged invoker picks up.
        if mode & 0o002 != 0 && mode & 0o1000 == 0 {
            details.push(format!(
                "{} mode {:o}",
                entry.display(),
                mode & 0o7777
            ));
        }
    }
    if details.is_empty() {
        return None;
    }
    Some(Finding {
        id: "writable_path",
        title: "World-writable directory in $PATH",
        severity: Severity::High,
        category: "privesc_local",
        details,
    })
}

fn check_writable_cron() -> Option<Finding> {
    let candidates = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron",
        "/var/spool/cron/crontabs",
    ];
    let mut details = Vec::new();
    for path in candidates {
        let p = Path::new(path);
        if !p.exists() {
            continue;
        }
        let Ok(meta) = fs::metadata(p) else { continue };
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 {
            details.push(format!("{path} world-writable ({:o})", mode & 0o7777));
        } else if is_writable_by_us(p) {
            details.push(format!("{path} writable by current user"));
        }
    }
    if details.is_empty() {
        return None;
    }
    Some(Finding {
        id: "writable_cron",
        title: "Writable cron path (root scheduler executes attacker code)",
        severity: Severity::Critical,
        category: "privesc_local",
        details,
    })
}

fn check_world_writable_systemd_units() -> Option<Finding> {
    let dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
    ];
    let mut details = Vec::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                details.push(format!(
                    "{} mode {:o}",
                    entry.path().display(),
                    mode & 0o7777
                ));
            }
        }
    }
    if details.is_empty() {
        return None;
    }
    Some(Finding {
        id: "world_writable_units",
        title: "World-writable systemd unit files",
        severity: Severity::Critical,
        category: "privesc_local",
        details,
    })
}

// Crude version-window match for a few well-known kernel CVEs. This is a
// triage hint, not a definitive vulnerability call. Each entry says
// "kernels in this range are *worth checking*".
struct KernelCveHint {
    cve: &'static str,
    name: &'static str,
    affected: fn((u64, u64, u64)) -> bool,
    poc_ref: &'static str,
}

const KERNEL_CVES: &[KernelCveHint] = &[
    KernelCveHint {
        cve: "CVE-2022-0847",
        name: "Dirty Pipe",
        affected: |(maj, min, _)| maj == 5 && (8..=16).contains(&min),
        poc_ref: "https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
    },
    KernelCveHint {
        cve: "CVE-2022-2588",
        name: "cls_route UAF",
        affected: |(maj, min, _)| maj == 5 && min < 19,
        poc_ref: "https://github.com/Markakd/CVE-2022-2588",
    },
    KernelCveHint {
        cve: "CVE-2023-32233",
        name: "nf_tables UAF",
        affected: |(maj, min, _)| maj == 6 && min <= 3,
        poc_ref: "https://github.com/Liuk3r/CVE-2023-32233",
    },
    KernelCveHint {
        cve: "CVE-2026-31431",
        name: "Copy Fail (AF_ALG + splice)",
        affected: |(maj, min, _)| maj == 6 && min <= 10,
        poc_ref: "https://github.com/theori-io/copy-fail-CVE-2026-31431",
    },
];

fn check_kernel_cve_window(release: Option<&str>) -> Option<Finding> {
    let release = release?;
    let parsed = parse_kernel_release(release)?;
    let mut details = Vec::new();
    for entry in KERNEL_CVES {
        if (entry.affected)(parsed) {
            details.push(format!(
                "{}: {} (in version window) — PoC: {}",
                entry.cve, entry.name, entry.poc_ref
            ));
        }
    }
    if details.is_empty() {
        return None;
    }
    Some(Finding {
        id: "kernel_cve_window",
        title: format!("Kernel {release} is in the version window of known CVEs").leak(),
        severity: Severity::High,
        category: "privesc_kernel",
        details,
    })
}

fn check_readable_secrets() -> Option<Finding> {
    let candidates = [
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_ed25519",
        "/root/.bash_history",
        "/root/.zsh_history",
        "/root/.kube/config",
        "/root/.aws/credentials",
        "/root/.docker/config.json",
        "/root/.netrc",
        "/etc/shadow",
        "/etc/gshadow",
        "/var/log/auth.log",
    ];
    let mut details = Vec::new();
    for path in candidates {
        if file_readable(path) {
            details.push(path.to_string());
        }
    }
    if details.is_empty() {
        return None;
    }
    Some(Finding {
        id: "readable_secrets",
        title: "Sensitive files readable as current user",
        severity: Severity::High,
        category: "privesc_local",
        details,
    })
}

fn check_caps_on_binaries() -> Option<Finding> {
    let getcap = which("getcap")?;
    let output = Command::new(getcap).arg("-r").arg("/usr/bin").output().ok()?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut details = Vec::new();
    let mut seen = BTreeSet::new();
    for line in combined.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // High-impact caps that turn a userland binary into a root primitive.
        let dangerous = [
            "cap_setuid",
            "cap_dac_read_search",
            "cap_dac_override",
            "cap_sys_admin",
            "cap_sys_module",
            "cap_sys_ptrace",
        ];
        if dangerous.iter().any(|d| trimmed.contains(d)) && seen.insert(trimmed.to_string()) {
            details.push(trimmed.to_string());
        }
    }
    if details.is_empty() {
        return None;
    }
    Some(Finding {
        id: "binary_capabilities",
        title: "User-runnable binaries with dangerous file capabilities",
        severity: Severity::High,
        category: "privesc_local",
        details,
    })
}

fn check_docker_group() -> Option<Finding> {
    let groups = read_self_groups();
    let in_docker_group = groups.iter().any(|g| g == "docker");
    if !in_docker_group {
        return None;
    }
    Some(Finding {
        id: "docker_group_membership",
        title: "Current user is in the 'docker' group → trivial root via docker run",
        severity: Severity::Critical,
        category: "privesc_local",
        details: vec![
            "docker run --rm -v /:/host -it alpine chroot /host sh".to_string(),
        ],
    })
}

// ---- helpers ----

fn read_self_uid() -> Option<u32> {
    read_status_first_u32(&fs::read_to_string("/proc/self/status").ok()?, "Uid:")
}

fn read_self_euid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Uid:")
            .and_then(|v| v.split_whitespace().nth(1).map(str::to_string))
            .and_then(|v| v.parse::<u32>().ok())
    })
}

fn read_status_first_u32(status: &str, key: &str) -> Option<u32> {
    status.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|v| v.split_whitespace().next().map(str::to_string))
            .and_then(|v| v.parse::<u32>().ok())
    })
}

fn read_self_groups() -> Vec<String> {
    // /proc/self/status has a Groups: line with numeric gids; resolving to
    // names requires /etc/group. We do the join here.
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let gids: Vec<u32> = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .map(|line| {
            line.split_whitespace()
                .filter_map(|s| s.parse::<u32>().ok())
                .collect()
        })
        .unwrap_or_default();
    let group_file = fs::read_to_string("/etc/group").unwrap_or_default();
    let mut names = Vec::new();
    for line in group_file.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 3 {
            continue;
        }
        if let Ok(gid) = parts[2].parse::<u32>() {
            if gids.contains(&gid) {
                names.push(parts[0].to_string());
            }
        }
    }
    names
}

fn read_kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn parse_kernel_release(release: &str) -> Option<(u64, u64, u64)> {
    let core = release.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = parts.next().and_then(|p| p.parse::<u64>().ok()).unwrap_or(0);
    Some((major, minor, patch))
}

fn file_readable(path: &str) -> bool {
    use std::io::Read;
    match fs::File::open(path) {
        Ok(mut f) => {
            let mut buf = [0_u8; 1];
            f.read(&mut buf).is_ok()
        }
        Err(_) => false,
    }
}

fn is_writable_by_us(path: &Path) -> bool {
    // Best-effort: try to open in append mode (creates nothing, succeeds
    // only if we can write). We immediately close.
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .map(|_| true)
        .unwrap_or(false)
}

fn which(binary: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&paths) {
        let candidate = entry.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_release_for_cve_lookup() {
        assert_eq!(parse_kernel_release("6.5.0-1-amd64"), Some((6, 5, 0)));
        assert_eq!(parse_kernel_release("garbage"), None);
    }

    #[test]
    fn cve_window_matches_dirty_pipe() {
        let finding =
            check_kernel_cve_window(Some("5.10.0-amd64")).expect("kernel 5.10 should hit");
        assert!(finding
            .details
            .iter()
            .any(|d| d.contains("Dirty Pipe")));
    }

    #[test]
    fn cve_window_skips_unrelated_kernel() {
        assert!(check_kernel_cve_window(Some("4.19.0")).is_none());
    }

    #[test]
    fn enumerate_runs_without_panic() {
        // Smoke test: on macOS the /proc reads return None and most checks
        // produce no findings. Just make sure nothing panics.
        let report = enumerate();
        // uid is None on macOS (no /proc/self/status) — both states are valid.
        let _ = report.uid;
        let _ = report.findings.len();
    }
}
