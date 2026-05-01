use crate::audit::HostAudit;
use crate::container::ContainerInfo;
use crate::monitor::MonitorStatus;
use crate::risk::RiskLevel;

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub host: HostAudit,
    pub containers: Vec<ContainerInfo>,
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

    AuditReport {
        host,
        containers,
        risk,
        reasons,
        recommendations,
    }
}

pub fn print_host_report(report: &AuditReport) {
    println!("Cornela Host Audit");
    println!("Risk: {}", report.risk);
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
}
