use crate::container::{CapabilityInfo, ContainerInfo, NamespaceInfo};
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
        "capabilities",
        &capability_json(&container.capabilities),
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

fn namespace_json(namespace: &NamespaceInfo) -> String {
    format!(
        "{{\"pid\":{},\"mnt\":{},\"net\":{},\"user\":{}}}",
        option_string(namespace.pid.as_deref()),
        option_string(namespace.mnt.as_deref()),
        option_string(namespace.net.as_deref()),
        option_string(namespace.user.as_deref())
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
