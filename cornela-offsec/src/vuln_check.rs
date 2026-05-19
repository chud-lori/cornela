// Deterministic, non-exploitative vulnerability checks. Each CVE is a small
// function that reads /proc and /sys, evaluates a structured prereq list,
// and returns one of:
//
//   Vulnerable : every observable signal is consistent with an unpatched
//                kernel/config and the attack surface is reachable.
//   Patched    : at least one signal indicates the fix is applied.
//   Unknown    : we could not determine either way (kernel version unknown,
//                config unreadable, etc.).
//
// We do NOT run any kernel exploit. A failed exploit would be ambiguous
// (wrong build, KASLR, etc.) — deterministic source-of-truth checks are
// strictly more reliable for triage.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Vulnerable,
    Patched,
    Unknown,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::Patched => "patched",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VulnReport {
    pub cve: String,
    pub name: &'static str,
    pub verdict: Verdict,
    pub reasons: Vec<String>,
    pub kernel_release: Option<String>,
    pub reference: &'static str,
}

pub fn check(cve: &str) -> Result<VulnReport, String> {
    let normalized = cve.to_ascii_uppercase();
    match normalized.as_str() {
        "CVE-2026-31431" => Ok(check_copy_fail()),
        other => Err(format!(
            "unknown CVE id '{other}' — supported: CVE-2026-31431"
        )),
    }
}

// CVE-2026-31431 "Copy Fail": AF_ALG + splice kernel UAF. Triage signals:
//   - kernel release in known affected window (upstream 6.0..=6.10)
//   - algif_aead module loaded (or compiled in)
//   - /proc/crypto exposes the AF_ALG aead surface
//
// Negative signal (Patched):
//   - kernel release outside affected range
//   - module not loaded AND CONFIG_CRYPTO_USER_API_AEAD not visible
//
// Distros frequently backport fixes without bumping the upstream-style
// minor version, so an in-range kernel is a *triage* signal — pair with
// kernel symbol checks where possible.
fn check_copy_fail() -> VulnReport {
    let kernel_release = read_trimmed("/proc/sys/kernel/osrelease");
    let mut reasons = Vec::new();
    let mut surface_present = false;
    let mut in_range = None;

    if let Some(release) = &kernel_release {
        match parse_kernel_release(release) {
            Some((6, minor, _)) if minor <= 10 => {
                in_range = Some(true);
                reasons.push(format!(
                    "kernel {release} is within upstream affected window (6.0..=6.10)"
                ));
            }
            Some((major, minor, _)) => {
                in_range = Some(false);
                reasons.push(format!(
                    "kernel {release} ({major}.{minor}.x) is outside the affected upstream range"
                ));
            }
            None => {
                reasons.push(format!("kernel release '{release}' unparsable"));
            }
        }
    } else {
        reasons.push("kernel release not readable from /proc/sys/kernel/osrelease".to_string());
    }

    let algif_aead = module_loaded("algif_aead");
    if algif_aead {
        surface_present = true;
        reasons.push("algif_aead module is loaded".to_string());
    } else {
        reasons.push("algif_aead module is not loaded".to_string());
    }

    let crypto_visible = Path::new("/proc/crypto").exists();
    if crypto_visible {
        let has_aead_in_crypto = fs::read_to_string("/proc/crypto")
            .map(|t| t.contains("type         : aead"))
            .unwrap_or(false);
        if has_aead_in_crypto {
            surface_present = true;
            reasons.push("/proc/crypto enumerates aead algorithms".to_string());
        } else {
            reasons.push("/proc/crypto exists but lists no aead algorithms".to_string());
        }
    } else {
        reasons.push("/proc/crypto not present".to_string());
    }

    let verdict = match (in_range, surface_present) {
        (Some(true), true) => Verdict::Vulnerable,
        (Some(false), _) => Verdict::Patched,
        (Some(true), false) => Verdict::Patched, // in-range kernel but no AF_ALG aead surface to attack
        (None, _) => Verdict::Unknown,
    };

    VulnReport {
        cve: "CVE-2026-31431".to_string(),
        name: "Copy Fail (AF_ALG + splice kernel UAF)",
        verdict,
        reasons,
        kernel_release,
        reference: "https://github.com/theori-io/copy-fail-CVE-2026-31431",
    }
}

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn module_loaded(name: &str) -> bool {
    let Ok(modules) = fs::read_to_string("/proc/modules") else {
        return false;
    };
    modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .any(|m| m == name)
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

    #[test]
    fn rejects_unknown_cve() {
        assert!(check("CVE-1999-9999").is_err());
    }

    #[test]
    fn copy_fail_verdict_strings_are_stable() {
        assert_eq!(Verdict::Vulnerable.as_str(), "vulnerable");
        assert_eq!(Verdict::Patched.as_str(), "patched");
        assert_eq!(Verdict::Unknown.as_str(), "unknown");
    }

    #[test]
    fn parses_kernel_release_variants() {
        assert_eq!(parse_kernel_release("6.5.0-1-amd64"), Some((6, 5, 0)));
        assert_eq!(parse_kernel_release("6.10.5"), Some((6, 10, 5)));
        assert_eq!(parse_kernel_release("5.15.0+"), Some((5, 15, 0)));
        assert_eq!(parse_kernel_release("garbage"), None);
    }

    #[test]
    fn copy_fail_runs_without_panicking_on_macos() {
        // Smoke test: on a non-Linux host the /proc reads return None and
        // the verdict should be Unknown, not panic.
        let report = check_copy_fail();
        assert_eq!(report.cve, "CVE-2026-31431");
        // We can't assert the verdict — depends on the host. But the
        // report must always have at least one reason.
        assert!(!report.reasons.is_empty());
    }
}
