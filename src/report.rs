use crate::audit::HostAudit;
use crate::container::ContainerInfo;
use crate::cve::CveScanResult;
use crate::monitor::MonitorStatus;
use crate::risk::RiskLevel;

#[derive(Debug, Clone)]
pub struct ReportMetadata {
    pub schema_version: u8,
    pub generated_at_unix_seconds: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RiskSummary {
    pub total_containers: usize,
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
}

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub metadata: ReportMetadata,
    pub host: HostAudit,
    pub containers: Vec<ContainerInfo>,
    pub cve_profiles: Vec<CveScanResult>,
    pub summary: RiskSummary,
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
    pub recommendations: Vec<String>,
}

pub fn build_report(host: HostAudit, containers: Vec<ContainerInfo>) -> AuditReport {
    let mut risk = host.risk;
    let mut reasons = host.reasons.clone();

    for container in &containers {
        risk = risk.max(container.risk);
        for reason in &container.reasons {
            reasons.push(format!("container {}: {reason}", short_id(&container.id)));
        }
    }

    let recommendations = build_recommendations(&host, &containers);
    let summary = summarize_risk(&containers);
    let cve_profiles = crate::cve::scan("CVE-2026-31431", &host, &containers)
        .map(|profile| vec![profile])
        .unwrap_or_default();

    AuditReport {
        metadata: ReportMetadata {
            schema_version: 1,
            generated_at_unix_seconds: current_unix_seconds(),
        },
        host,
        containers,
        cve_profiles,
        summary,
        risk,
        reasons,
        recommendations,
    }
}

pub fn print_host_report(report: &AuditReport) {
    println!("Cornela Host Audit");
    println!("Risk: {}", report.risk);
    println!("Report schema: {}", report.metadata.schema_version);
    println!(
        "Generated at: {}",
        report.metadata.generated_at_unix_seconds
    );
    println!("OS: {}", report.host.operating_system);
    println!(
        "Linux audit support: {}",
        if report.host.linux_supported {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Kernel: {}",
        report.host.kernel_version.as_deref().unwrap_or("unknown")
    );
    println!("algif_aead: {}", yes_no(report.host.algif_aead_loaded));
    println!("AF_ALG signal: {}", yes_no(report.host.af_alg_available));
    println!("seccomp: {}", yes_no(report.host.seccomp_available));
    println!("AppArmor: {}", yes_no(report.host.apparmor_enabled));
    println!("SELinux: {}", yes_no(report.host.selinux_enabled));
    println!(
        "user namespaces: {}",
        match report.host.user_namespaces_enabled {
            Some(true) => "enabled",
            Some(false) => "disabled",
            None => "unknown",
        }
    );
    println!(
        "container runtimes: {}",
        if report.host.runtimes.is_empty() {
            "none detected".to_string()
        } else {
            report.host.runtimes.join(", ")
        }
    );
    println!("containers detected: {}", report.containers.len());
    println!(
        "container risk summary: low={}, medium={}, high={}, critical={}",
        report.summary.low, report.summary.medium, report.summary.high, report.summary.critical
    );

    if !report.reasons.is_empty() {
        println!();
        println!("Reasons:");
        for reason in &report.reasons {
            println!("- {reason}");
        }
    }

    if !report.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for recommendation in &report.recommendations {
            println!("- {recommendation}");
        }
    }

    if !report.cve_profiles.is_empty() {
        println!();
        println!("CVE Profiles:");
        for profile in &report.cve_profiles {
            println!(
                "- {} {}: status={}, risk={}",
                profile.id,
                profile.name,
                profile.status.as_str(),
                profile.risk
            );
        }
    }
}

pub fn print_cve_scan(scan: &CveScanResult) {
    println!("Cornela CVE Profile");
    println!("ID: {}", scan.id);
    println!("Name: {}", scan.name);
    println!("Status: {}", scan.status.as_str());
    println!("Risk: {}", scan.risk);
    println!(
        "Kernel: {}",
        scan.kernel_assessment
            .version
            .as_deref()
            .unwrap_or("unknown")
    );
    println!("Kernel note: {}", scan.kernel_assessment.note);

    if !scan.signals.is_empty() {
        println!();
        println!("Signals:");
        for signal in &scan.signals {
            println!(
                "- {}: {} ({})",
                signal.name,
                yes_no(signal.present),
                signal.detail
            );
        }
    }

    if !scan.reasons.is_empty() {
        println!();
        println!("Reasons:");
        for reason in &scan.reasons {
            println!("- {reason}");
        }
    }

    if !scan.recommendations.is_empty() {
        println!();
        println!("Recommendations:");
        for recommendation in &scan.recommendations {
            println!("- {recommendation}");
        }
    }
}

pub fn print_containers(containers: &[ContainerInfo]) {
    if containers.is_empty() {
        println!("No container-like cgroups detected.");
        return;
    }

    for container in containers {
        println!("Container: {}", short_id(&container.id));
        println!(
            "  Runtime: {}",
            container.runtime.as_deref().unwrap_or("unknown")
        );
        println!("  Risk: {}", container.risk);
        println!("  PIDs: {}", join_pids(&container.pids));
        if let Some(process) = &container.process {
            println!("  Representative PID: {}", process.pid);
            if let Some(name) = &process.name {
                println!("  Process: {name}");
            }
            if let Some(command_line) = &process.command_line {
                println!("  Command: {command_line}");
            }
        }
        println!(
            "  Seccomp: {}",
            container
                .security
                .seccomp_mode
                .map(|mode| mode.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        println!(
            "  NoNewPrivs: {}",
            container
                .security
                .no_new_privs
                .map(yes_no)
                .unwrap_or("unknown")
        );
        println!(
            "  CapEff: {}",
            container
                .capabilities
                .effective_hex
                .as_deref()
                .unwrap_or("unknown")
        );
        println!(
            "  Host namespaces: pid={}, mnt={}, net={}",
            yes_no(container.namespace_risk.host_pid_namespace),
            yes_no(container.namespace_risk.host_mount_namespace),
            yes_no(container.namespace_risk.host_network_namespace)
        );
        if !container.reasons.is_empty() {
            println!("  Reasons:");
            for reason in &container.reasons {
                println!("  - {reason}");
            }
        }
        println!();
    }
}

pub fn print_monitor_status(status: &MonitorStatus) {
    println!("Cornela Runtime Monitor");
    println!("OS: {}", status.operating_system);
    println!("Linux support: {}", yes_no(status.linux_supported));
    println!("eBPF loader ready: {}", yes_no(status.loader_ready));
    println!(
        "event enrichment ready: {}",
        yes_no(status.event_enrichment_ready)
    );
    println!(
        "sequence tracking ready: {}",
        yes_no(status.sequence_tracking_ready)
    );
    println!("sequence window: {}s", status.sequence_window_seconds);
    if let Some(duration) = status.duration_seconds {
        println!("requested duration: {duration}s");
    }
    println!("planned probes: {}", status.planned_probes.join(", "));

    if !status.reasons.is_empty() {
        println!();
        println!("Reasons:");
        for reason in &status.reasons {
            println!("- {reason}");
        }
    }
}

fn yes_no(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

fn join_pids(pids: &[u32]) -> String {
    pids.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn short_id(id: &str) -> &str {
    id.get(..12).unwrap_or(id)
}

fn build_recommendations(host: &HostAudit, containers: &[ContainerInfo]) -> Vec<String> {
    let mut recommendations = Vec::new();

    if !host.linux_supported {
        recommendations.push(
            "Run Cornela on the Linux container host or VM for kernel-level audit results."
                .to_string(),
        );
        recommendations.sort();
        recommendations.dedup();
        return recommendations;
    }

    if host.algif_aead_loaded || host.af_alg_available {
        recommendations.push(
            "Review seccomp policy coverage for AF_ALG and kernel crypto interfaces.".to_string(),
        );
    }

    if !host.seccomp_available {
        recommendations.push(
            "Enable seccomp support and enforce container seccomp profiles where possible."
                .to_string(),
        );
    }

    if !host.apparmor_enabled && !host.selinux_enabled {
        recommendations
            .push("Enable AppArmor or SELinux enforcement on Linux container hosts.".to_string());
    }

    for container in containers {
        if matches!(container.security.seccomp_mode, Some(0) | None) {
            recommendations.push(format!(
                "Apply a seccomp profile to container {}.",
                short_id(&container.id)
            ));
        }

        if container.capabilities.has_cap_sys_admin || container.capabilities.has_cap_sys_module {
            recommendations.push(format!(
                "Drop high-risk capabilities from container {}.",
                short_id(&container.id)
            ));
        }

        if container.namespace_risk.host_pid_namespace
            || container.namespace_risk.host_mount_namespace
            || container.namespace_risk.host_network_namespace
        {
            recommendations.push(format!(
                "Avoid host namespace sharing for container {} unless explicitly required.",
                short_id(&container.id)
            ));
        }
    }

    recommendations.sort();
    recommendations.dedup();
    recommendations
}

fn summarize_risk(containers: &[ContainerInfo]) -> RiskSummary {
    let mut summary = RiskSummary {
        total_containers: containers.len(),
        ..RiskSummary::default()
    };

    for container in containers {
        match container.risk {
            RiskLevel::Low => summary.low += 1,
            RiskLevel::Medium => summary.medium += 1,
            RiskLevel::High => summary.high += 1,
            RiskLevel::Critical => summary.critical += 1,
        }
    }

    summary
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_recommends_linux_for_non_linux_hosts() {
        let host = HostAudit {
            operating_system: "macos".to_string(),
            linux_supported: false,
            kernel_version: Some("24.6.0".to_string()),
            loaded_modules: Vec::new(),
            algif_aead_loaded: false,
            af_alg_available: false,
            seccomp_available: false,
            apparmor_enabled: false,
            selinux_enabled: false,
            user_namespaces_enabled: None,
            runtimes: Vec::new(),
            risk: RiskLevel::Medium,
            reasons: vec!["unsupported platform".to_string()],
        };

        let report = build_report(host, Vec::new());

        assert!(report
            .recommendations
            .iter()
            .any(|recommendation| recommendation.contains("Run Cornela on the Linux")));
    }

    #[test]
    fn summarizes_container_risk_counts() {
        let mut low = minimal_container("aaaaaaaaaaaa");
        low.risk = RiskLevel::Low;
        let mut high = minimal_container("bbbbbbbbbbbb");
        high.risk = RiskLevel::High;

        let summary = summarize_risk(&[low, high]);

        assert_eq!(summary.total_containers, 2);
        assert_eq!(summary.low, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 0);
    }

    fn minimal_container(id: &str) -> ContainerInfo {
        ContainerInfo {
            id: id.to_string(),
            runtime: None,
            pids: Vec::new(),
            process: None,
            cgroup_paths: Vec::new(),
            namespaces: Default::default(),
            namespace_risk: Default::default(),
            capabilities: Default::default(),
            security: Default::default(),
            risk: RiskLevel::Low,
            reasons: Vec::new(),
        }
    }
}
