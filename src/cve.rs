use crate::audit::HostAudit;
use crate::container::ContainerInfo;
use crate::risk::{RiskAssessment, RiskLevel};

const COPY_FAIL_ID: &str = "CVE-2026-31431";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveScanResult {
    pub id: String,
    pub name: String,
    pub status: CveExposureStatus,
    pub risk: RiskLevel,
    pub kernel_assessment: KernelAssessment,
    pub signals: Vec<CveSignal>,
    pub reasons: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CveExposureStatus {
    Unsupported,
    NotDetected,
    Possible,
    Likely,
    Mitigated,
}

impl CveExposureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::NotDetected => "not_detected",
            Self::Possible => "possible",
            Self::Likely => "likely",
            Self::Mitigated => "mitigated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelAssessment {
    pub version: Option<String>,
    pub parsed: Option<KernelVersion>,
    pub fixed_by_upstream_version: Option<bool>,
    pub note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    pub release_candidate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveSignal {
    pub name: String,
    pub present: bool,
    pub detail: String,
}

pub fn scan(
    id: &str,
    host: &HostAudit,
    containers: &[ContainerInfo],
) -> Result<CveScanResult, String> {
    if !id.eq_ignore_ascii_case(COPY_FAIL_ID) {
        return Err(format!("unsupported CVE profile: {id}"));
    }

    Ok(scan_copy_fail(host, containers))
}

fn scan_copy_fail(host: &HostAudit, containers: &[ContainerInfo]) -> CveScanResult {
    let kernel_assessment = if host.linux_supported {
        assess_kernel(host.kernel_version.as_deref())
    } else {
        KernelAssessment {
            version: host.kernel_version.clone(),
            parsed: None,
            fixed_by_upstream_version: None,
            note: "not assessed because the current host is not Linux".to_string(),
        }
    };
    let mut assessment = RiskAssessment::new();
    let mut signals = Vec::new();
    let mut recommendations = Vec::new();

    if !host.linux_supported {
        assessment.add(
            RiskLevel::Medium,
            "CVE-2026-31431 can only be assessed on the Linux kernel host",
        );
        recommendations.push(
            "Run this profile on the Linux host or VM that actually runs the containers."
                .to_string(),
        );

        return CveScanResult {
            id: COPY_FAIL_ID.to_string(),
            name: "Copy Fail".to_string(),
            status: CveExposureStatus::Unsupported,
            risk: assessment.level,
            kernel_assessment,
            signals,
            reasons: assessment.reasons(),
            recommendations,
        };
    }

    if matches!(kernel_assessment.fixed_by_upstream_version, Some(false)) {
        assessment.add(
            RiskLevel::High,
            "kernel version falls in the upstream affected range heuristic",
        );
    } else if matches!(kernel_assessment.fixed_by_upstream_version, Some(true)) {
        assessment.add_info("kernel version appears fixed by upstream version heuristic");
    } else {
        assessment.add(
            RiskLevel::Medium,
            "kernel version could not be mapped to an upstream fixed range",
        );
    }

    push_signal(
        &mut signals,
        "algif_aead_loaded",
        host.algif_aead_loaded,
        "algif_aead module is loaded",
    );
    if host.algif_aead_loaded {
        assessment.add(RiskLevel::High, "algif_aead module is currently loaded");
    }

    push_signal(
        &mut signals,
        "af_alg_available",
        host.af_alg_available,
        "kernel crypto API signal is present",
    );
    if host.af_alg_available {
        assessment.add(
            RiskLevel::Medium,
            "kernel crypto API appears available to local processes",
        );
    }

    push_signal(
        &mut signals,
        "seccomp_available",
        host.seccomp_available,
        "seccomp support was detected",
    );
    if !host.seccomp_available {
        assessment.add(
            RiskLevel::Medium,
            "seccomp support was not detected, so AF_ALG filtering may be absent",
        );
    }

    let container_count = containers.len();
    push_signal(
        &mut signals,
        "containers_detected",
        container_count > 0,
        &format!("{container_count} container-like cgroup groups detected"),
    );
    if container_count > 0 {
        assessment.add(
            RiskLevel::Medium,
            "containers share the host kernel, so local kernel LPE exposure can become container escape risk",
        );
    }

    let status = if matches!(kernel_assessment.fixed_by_upstream_version, Some(true)) {
        CveExposureStatus::Mitigated
    } else if host.algif_aead_loaded && host.af_alg_available {
        CveExposureStatus::Likely
    } else if assessment.level >= RiskLevel::Medium {
        CveExposureStatus::Possible
    } else {
        CveExposureStatus::NotDetected
    };

    if status != CveExposureStatus::Mitigated {
        recommendations.push("Patch the Linux kernel to a vendor-fixed build.".to_string());
        recommendations.push(
            "Temporarily disable or block algif_aead/AF_ALG AEAD access where operationally safe."
                .to_string(),
        );
        recommendations.push(
            "Use seccomp to block unnecessary AF_ALG socket creation in untrusted containers."
                .to_string(),
        );
    }
    recommendations.push(
        "Treat this result as exposure triage; confirm patched status with vendor advisories and package metadata."
            .to_string(),
    );

    recommendations.sort();
    recommendations.dedup();

    CveScanResult {
        id: COPY_FAIL_ID.to_string(),
        name: "Copy Fail".to_string(),
        status,
        risk: assessment.level,
        kernel_assessment,
        signals,
        reasons: assessment.reasons(),
        recommendations,
    }
}

fn push_signal(signals: &mut Vec<CveSignal>, name: &str, present: bool, detail: &str) {
    signals.push(CveSignal {
        name: name.to_string(),
        present,
        detail: detail.to_string(),
    });
}

fn assess_kernel(version: Option<&str>) -> KernelAssessment {
    let parsed = version.and_then(parse_kernel_version);
    let fixed_by_upstream_version = parsed.map(is_fixed_by_upstream_version);
    let note = match fixed_by_upstream_version {
        Some(true) => "kernel version is at or above the public upstream fixed range".to_string(),
        Some(false) => {
            "kernel version is in the public upstream affected range heuristic".to_string()
        }
        None => "kernel version could not be parsed; distro backports must be checked".to_string(),
    };

    KernelAssessment {
        version: version.map(str::to_string),
        parsed,
        fixed_by_upstream_version,
        note,
    }
}

fn is_fixed_by_upstream_version(version: KernelVersion) -> bool {
    if version.release_candidate {
        return false;
    }

    if version.major >= 7 {
        return true;
    }

    if version.major == 6 && version.minor == 19 {
        return version.patch >= 12;
    }

    if version.major == 6 && version.minor == 18 {
        return version.patch >= 22;
    }

    false
}

fn parse_kernel_version(version: &str) -> Option<KernelVersion> {
    let release_candidate = version.contains("-rc");
    let numeric = version
        .split(|char: char| !(char.is_ascii_digit() || char == '.'))
        .find(|part| !part.is_empty())?;
    let mut parts = numeric.split('.');

    Some(KernelVersion {
        major: parts.next()?.parse().ok()?,
        minor: parts.next().unwrap_or("0").parse().ok()?,
        patch: parts.next().unwrap_or("0").parse().ok()?,
        release_candidate,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_versions() {
        assert_eq!(
            parse_kernel_version("6.18.22-100-generic"),
            Some(KernelVersion {
                major: 6,
                minor: 18,
                patch: 22,
                release_candidate: false,
            })
        );
        assert_eq!(
            parse_kernel_version("7.0.0-rc3"),
            Some(KernelVersion {
                major: 7,
                minor: 0,
                patch: 0,
                release_candidate: true,
            })
        );
    }

    #[test]
    fn assesses_upstream_fixed_versions() {
        assert!(is_fixed_by_upstream_version(KernelVersion {
            major: 6,
            minor: 18,
            patch: 22,
            release_candidate: false,
        }));
        assert!(is_fixed_by_upstream_version(KernelVersion {
            major: 6,
            minor: 19,
            patch: 12,
            release_candidate: false,
        }));
        assert!(!is_fixed_by_upstream_version(KernelVersion {
            major: 6,
            minor: 18,
            patch: 21,
            release_candidate: false,
        }));
        assert!(!is_fixed_by_upstream_version(KernelVersion {
            major: 7,
            minor: 0,
            patch: 0,
            release_candidate: true,
        }));
    }
}
