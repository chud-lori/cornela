use std::env;
use std::fs;
use std::path::Path;

use crate::risk::{RiskAssessment, RiskLevel};

#[derive(Debug, Clone)]
pub struct HostAudit {
    pub operating_system: String,
    pub linux_supported: bool,
    pub kernel_version: Option<String>,
    pub loaded_modules: Vec<String>,
    pub algif_aead_loaded: bool,
    pub af_alg_available: bool,
    pub seccomp_available: bool,
    pub apparmor_enabled: bool,
    pub selinux_enabled: bool,
    pub user_namespaces_enabled: Option<bool>,
    pub runtimes: Vec<String>,
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
}

pub fn run_host_audit() -> HostAudit {
    let operating_system = env::consts::OS.to_string();
    let linux_supported = operating_system == "linux";
    let kernel_version =
        read_trimmed("/proc/sys/kernel/osrelease").or_else(|| command_output("uname", &["-r"]));

    if !linux_supported {
        return HostAudit {
            operating_system: operating_system.clone(),
            linux_supported,
            kernel_version,
            loaded_modules: Vec::new(),
            algif_aead_loaded: false,
            af_alg_available: false,
            seccomp_available: false,
            apparmor_enabled: false,
            selinux_enabled: false,
            user_namespaces_enabled: None,
            runtimes: detect_runtimes(),
            risk: RiskLevel::Medium,
            reasons: vec![format!(
                "Cornela host audit is designed for Linux; current OS is {operating_system}"
            )],
        };
    }

    let loaded_modules = read_loaded_modules();
    let algif_aead_loaded = loaded_modules.iter().any(|module| module == "algif_aead");
    let af_alg_available = Path::new("/proc/crypto").exists();
    let seccomp_available =
        Path::new("/proc/sys/kernel/seccomp").exists() || read_status_seccomp().is_some();
    let apparmor_enabled = apparmor_active();
    let selinux_enabled = selinux_enforcing();
    let user_namespaces_enabled = read_trimmed("/proc/sys/user/max_user_namespaces")
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value > 0);
    let runtimes = detect_runtimes();

    let mut assessment = RiskAssessment::new();

    if algif_aead_loaded {
        assessment.add(RiskLevel::Medium, "algif_aead kernel module is loaded");
    }

    if af_alg_available {
        assessment.add(
            RiskLevel::Medium,
            "kernel crypto API is exposed through /proc/crypto",
        );
    }

    if !seccomp_available {
        assessment.add(RiskLevel::Medium, "seccomp support was not detected");
    }

    if !apparmor_enabled && !selinux_enabled {
        assessment.add(
            RiskLevel::Medium,
            "neither AppArmor nor SELinux appears active",
        );
    }

    if matches!(user_namespaces_enabled, Some(false)) {
        assessment.add_info("user namespaces appear disabled");
    }

    if runtimes.is_empty() {
        assessment.add_info("no common container runtime binary was found in PATH");
    }

    HostAudit {
        operating_system,
        linux_supported,
        kernel_version,
        loaded_modules,
        algif_aead_loaded,
        af_alg_available,
        seccomp_available,
        apparmor_enabled,
        selinux_enabled,
        user_namespaces_enabled,
        runtimes,
        risk: assessment.level,
        reasons: assessment.reasons(),
    }
}

// AppArmor: the module-enabled flag alone is not enough — a kernel with
// AppArmor compiled in but no profiles loaded will still report enabled. Walk
// /sys/kernel/security/apparmor/profiles and require at least one entry in
// "enforce" mode to call AppArmor active. Falls back to the legacy
// module-enabled check if the profiles file is unreadable (e.g. monitor
// running without CAP_MAC_ADMIN).
fn apparmor_active() -> bool {
    if let Ok(profiles) = fs::read_to_string("/sys/kernel/security/apparmor/profiles") {
        return profiles.lines().any(|line| line.contains("(enforce)"));
    }
    read_trimmed("/sys/module/apparmor/parameters/enabled")
        .map(|value| matches!(value.as_str(), "Y" | "y" | "1"))
        .unwrap_or(false)
}

// SELinux: file existence proves the LSM is mounted, not that it's
// enforcing. Permissive mode (`enforce` contains "0") still creates the file
// but does not block anything. Treat only "1" as actively enforcing.
fn selinux_enforcing() -> bool {
    read_trimmed("/sys/fs/selinux/enforce")
        .map(|value| value == "1")
        .unwrap_or(false)
}

fn read_loaded_modules() -> Vec<String> {
    let Ok(modules) = fs::read_to_string("/proc/modules") else {
        return Vec::new();
    };

    modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

fn read_status_seccomp() -> Option<u8> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("Seccomp:")
            .and_then(|value| value.trim().parse::<u8>().ok())
    })
}

fn detect_runtimes() -> Vec<String> {
    ["docker", "containerd", "crictl", "podman", "kubectl"]
        .iter()
        .filter(|runtime| binary_in_path(runtime))
        .map(|runtime| (*runtime).to_string())
        .collect()
}

fn binary_in_path(binary: &str) -> bool {
    let Some(paths) = env::var_os("PATH") else {
        return false;
    };

    env::split_paths(&paths).any(|path| path.join(binary).is_file())
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
}

fn command_output(command: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(command)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_module_names_from_proc_modules_format() {
        let modules = "algif_aead 16384 0 - Live 0xffffffffc0000000\nbridge 409600 0 - Live 0xffffffffc0010000\n";
        let parsed: Vec<String> = modules
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_string)
            .collect();

        assert!(parsed.iter().any(|module| module == "algif_aead"));
        assert!(parsed.iter().any(|module| module == "bridge"));
    }

    #[test]
    fn risk_level_order_supports_escalation() {
        assert!(RiskLevel::High > RiskLevel::Medium);
        assert_eq!(RiskLevel::Low.max(RiskLevel::Medium), RiskLevel::Medium);
    }
}
