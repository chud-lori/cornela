use crate::container::{
    CapabilityInfo, ContainerInfo, NamespaceInfo, NamespaceRisk, ProcessInfo, SecurityProfile,
};
use crate::event::RuntimeEvent;
use crate::monitor::MonitorStatus;
use crate::report::AuditReport;

pub fn report_to_json(report: &AuditReport) -> String {
    let mut json = String::new();
    json.push_str("{\n");
    field(&mut json, 1, "tool", "\"cornela\"", true);
    field(
        &mut json,
        1,
        "subtitle",
        "\"Container Kernel Auditor for eBPF-based escape risk detection\"",
        true,
    );
    field(
        &mut json,
        1,
        "risk",
        &format!("\"{}\"", report.risk.as_str()),
        true,
    );
    field(&mut json, 1, "host", &host_json(report), true);
    field(
        &mut json,
        1,
        "containers",
        &containers_to_json_inner(&report.containers, 1),
        true,
    );
    field(
        &mut json,
        1,
        "reasons",
        &string_array(&report.reasons, 1),
        true,
    );
    field(
        &mut json,
        1,
        "recommendations",
        &string_array(&report.recommendations, 1),
        false,
    );
    json.push_str("}\n");
    json
}

pub fn containers_to_json(containers: &[ContainerInfo]) -> String {
    let mut json = containers_to_json_inner(containers, 0);
    json.push('\n');
    json
}

pub fn monitor_status_to_json(status: &MonitorStatus) -> String {
    let mut json = String::new();
    json.push_str("{\n");
    field(&mut json, 1, "status", "\"preflight\"", true);
    field(
        &mut json,
        1,
        "operating_system",
        &quoted(&status.operating_system),
        true,
    );
    field(
        &mut json,
        1,
        "linux_supported",
        bool_json(status.linux_supported),
        true,
    );
    field(
        &mut json,
        1,
        "loader_ready",
        bool_json(status.loader_ready),
        true,
    );
    field(
        &mut json,
        1,
        "duration_seconds",
        &option_u64(status.duration_seconds),
        true,
    );
    field(
        &mut json,
        1,
        "planned_probes",
        &string_array(&status.planned_probes, 1),
        true,
    );
    field(
        &mut json,
        1,
        "reasons",
        &string_array(&status.reasons, 1),
        false,
    );
    json.push_str("}\n");
    json
}

#[allow(dead_code)]
pub fn runtime_event_to_json(event: &RuntimeEvent) -> String {
    let mut json = String::new();
    json.push_str("{\n");
    field(
        &mut json,
        1,
        "type",
        &quoted(event.event_type.as_str()),
        true,
    );
    field(
        &mut json,
        1,
        "severity",
        &quoted(event.severity.as_str()),
        true,
    );
    field(&mut json, 1, "pid", &event.pid.to_string(), true);
    field(&mut json, 1, "uid", &option_u32(event.uid), true);
    field(&mut json, 1, "gid", &option_u32(event.gid), true);
    field(&mut json, 1, "comm", &quoted(&event.comm), true);
    field(
        &mut json,
        1,
        "container_id",
        &option_string(event.container_id.as_deref()),
        true,
    );
    field(
        &mut json,
        1,
        "syscall",
        &option_string(event.syscall.as_deref()),
        true,
    );
    field(&mut json, 1, "detail", &quoted(&event.detail), true);
    field(
        &mut json,
        1,
        "timestamp_ns",
        &event.timestamp_ns.to_string(),
        false,
    );
    json.push_str("}\n");
    json
}

fn host_json(report: &AuditReport) -> String {
    let host = &report.host;
    let mut json = String::new();
    json.push_str("{\n");
    field(
        &mut json,
        2,
        "operating_system",
        &quoted(&host.operating_system),
        true,
    );
    field(
        &mut json,
        2,
        "linux_supported",
        bool_json(host.linux_supported),
        true,
    );
    field(
        &mut json,
        2,
        "kernel_version",
        &option_string(host.kernel_version.as_deref()),
        true,
    );
    field(
        &mut json,
        2,
        "algif_aead_loaded",
        bool_json(host.algif_aead_loaded),
        true,
    );
    field(
        &mut json,
        2,
        "af_alg_available",
        bool_json(host.af_alg_available),
        true,
    );
    field(
        &mut json,
        2,
        "seccomp_available",
        bool_json(host.seccomp_available),
        true,
    );
    field(
        &mut json,
        2,
        "apparmor_enabled",
        bool_json(host.apparmor_enabled),
        true,
    );
    field(
        &mut json,
        2,
        "selinux_enabled",
        bool_json(host.selinux_enabled),
        true,
    );
    field(
        &mut json,
        2,
        "user_namespaces_enabled",
        &option_bool(host.user_namespaces_enabled),
        true,
    );
    field(
        &mut json,
        2,
        "runtimes",
        &string_array(&host.runtimes, 2),
        true,
    );
    field(
        &mut json,
        2,
        "loaded_modules_count",
        &host.loaded_modules.len().to_string(),
        true,
    );
    field(
        &mut json,
        2,
        "risk",
        &format!("\"{}\"", host.risk.as_str()),
        true,
    );
    field(
        &mut json,
        2,
        "reasons",
        &string_array(&host.reasons, 2),
        false,
    );
    json.push_str("  }");
    json
}

fn containers_to_json_inner(containers: &[ContainerInfo], indent: usize) -> String {
    if containers.is_empty() {
        return "[]".to_string();
    }

    let mut json = String::new();
    json.push_str("[\n");
    for (index, container) in containers.iter().enumerate() {
        json.push_str(&indent_str(indent + 1));
        json.push_str(&container_json(container, indent + 1));
        if index + 1 != containers.len() {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str(&indent_str(indent));
    json.push(']');
    json
}

fn container_json(container: &ContainerInfo, indent: usize) -> String {
    let mut json = String::new();
    json.push_str("{\n");
    field(&mut json, indent + 1, "id", &quoted(&container.id), true);
    field(
        &mut json,
        indent + 1,
        "runtime",
        &option_string(container.runtime.as_deref()),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "pids",
        &u32_array(&container.pids),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "process",
        &process_json(container.process.as_ref()),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "cgroup_paths",
        &string_array(&container.cgroup_paths, indent + 1),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "namespaces",
        &namespace_json(&container.namespaces),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "namespace_risk",
        &namespace_risk_json(&container.namespace_risk),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "capabilities",
        &capability_json(&container.capabilities),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "security",
        &security_json(&container.security),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "risk",
        &format!("\"{}\"", container.risk.as_str()),
        true,
    );
    field(
        &mut json,
        indent + 1,
        "reasons",
        &string_array(&container.reasons, indent + 1),
        false,
    );
    json.push_str(&indent_str(indent));
    json.push('}');
    json
}

fn process_json(process: Option<&ProcessInfo>) -> String {
    let Some(process) = process else {
        return "null".to_string();
    };

    format!(
        "{{\"pid\":{},\"ppid\":{},\"uid\":{},\"gid\":{},\"name\":{},\"command_line\":{}}}",
        process.pid,
        option_u32(process.ppid),
        option_u32(process.uid),
        option_u32(process.gid),
        option_string(process.name.as_deref()),
        option_string(process.command_line.as_deref())
    )
}

fn namespace_json(namespace: &NamespaceInfo) -> String {
    format!(
        "{{\"pid\":{},\"mnt\":{},\"net\":{},\"user\":{}}}",
        option_string(namespace.pid.as_deref()),
        option_string(namespace.mnt.as_deref()),
        option_string(namespace.net.as_deref()),
        option_string(namespace.user.as_deref())
    )
}

fn namespace_risk_json(namespace: &NamespaceRisk) -> String {
    format!(
        "{{\"host_pid_namespace\":{},\"host_mount_namespace\":{},\"host_network_namespace\":{}}}",
        bool_json(namespace.host_pid_namespace),
        bool_json(namespace.host_mount_namespace),
        bool_json(namespace.host_network_namespace)
    )
}

fn capability_json(capability: &CapabilityInfo) -> String {
    format!(
        "{{\"effective_hex\":{},\"cap_sys_admin\":{},\"cap_sys_module\":{},\"cap_sys_ptrace\":{},\"cap_net_admin\":{}}}",
        option_string(capability.effective_hex.as_deref()),
        bool_json(capability.has_cap_sys_admin),
        bool_json(capability.has_cap_sys_module),
        bool_json(capability.has_cap_sys_ptrace),
        bool_json(capability.has_cap_net_admin)
    )
}

fn security_json(security: &SecurityProfile) -> String {
    format!(
        "{{\"seccomp_mode\":{},\"no_new_privs\":{}}}",
        security
            .seccomp_mode
            .map(|value| value.to_string())
            .unwrap_or_else(|| "null".to_string()),
        option_bool(security.no_new_privs)
    )
}

fn field(json: &mut String, indent: usize, key: &str, value: &str, comma: bool) {
    json.push_str(&indent_str(indent));
    json.push_str(&quoted(key));
    json.push_str(": ");
    json.push_str(value);
    if comma {
        json.push(',');
    }
    json.push('\n');
}

fn string_array(values: &[String], indent: usize) -> String {
    if values.is_empty() {
        return "[]".to_string();
    }

    let mut json = String::new();
    json.push_str("[\n");
    for (index, value) in values.iter().enumerate() {
        json.push_str(&indent_str(indent + 1));
        json.push_str(&quoted(value));
        if index + 1 != values.len() {
            json.push(',');
        }
        json.push('\n');
    }
    json.push_str(&indent_str(indent));
    json.push(']');
    json
}

fn u32_array(values: &[u32]) -> String {
    let values = values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("[{values}]")
}

fn option_string(value: Option<&str>) -> String {
    value.map(quoted).unwrap_or_else(|| "null".to_string())
}

fn option_bool(value: Option<bool>) -> String {
    value.map(bool_json).unwrap_or("null").to_string()
}

fn option_u32(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn bool_json(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn quoted(value: &str) -> String {
    let escaped = value
        .chars()
        .flat_map(|char| match char {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect::<Vec<_>>(),
            '\n' => "\\n".chars().collect::<Vec<_>>(),
            '\r' => "\\r".chars().collect::<Vec<_>>(),
            '\t' => "\\t".chars().collect::<Vec<_>>(),
            other => vec![other],
        })
        .collect::<String>();
    format!("\"{escaped}\"")
}

fn indent_str(indent: usize) -> String {
    "  ".repeat(indent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_json_string_content() {
        assert_eq!(
            quoted("quote \" slash \\ newline\n tab\t"),
            "\"quote \\\" slash \\\\ newline\\n tab\\t\""
        );
    }

    #[test]
    fn serializes_empty_containers_as_array() {
        assert_eq!(containers_to_json(&[]), "[]\n");
    }

    #[test]
    fn serializes_monitor_preflight() {
        let status = MonitorStatus {
            operating_system: "linux".to_string(),
            linux_supported: true,
            loader_ready: false,
            duration_seconds: Some(5),
            planned_probes: vec!["tracepoint/syscalls/sys_enter_socket".to_string()],
            reasons: vec!["loader pending".to_string()],
        };

        let json = monitor_status_to_json(&status);

        assert!(json.contains("\"status\": \"preflight\""));
        assert!(json.contains("\"duration_seconds\": 5"));
        assert!(json.contains("tracepoint/syscalls/sys_enter_socket"));
    }
}
