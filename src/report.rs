use crate::audit::HostAudit;
use crate::cli::OutputMode;
use crate::container::ContainerInfo;
use crate::risk::RiskLevel;

#[derive(Debug, Clone)]
pub struct AuditReport {
    pub host: HostAudit,
    pub containers: Vec<ContainerInfo>,
    pub risk: RiskLevel,
    pub reasons: Vec<String>,
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

    AuditReport {
        host,
        containers,
        risk,
        reasons,
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
        println!(
            "  CapEff: {}",
            container
                .capabilities
                .effective_hex
                .as_deref()
                .unwrap_or("unknown")
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

pub fn print_monitor_placeholder(output: OutputMode) {
    match output {
        OutputMode::Text => {
            println!("Cornela runtime monitor is not implemented yet.");
            println!(
                "Planned eBPF probes: sys_enter_socket, sys_enter_splice, sched_process_exec."
            );
        }
        OutputMode::Json => {
            println!(
                "{{\"status\":\"not_implemented\",\"planned_probes\":[\"sys_enter_socket\",\"sys_enter_splice\",\"sched_process_exec\"]}}"
            );
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
