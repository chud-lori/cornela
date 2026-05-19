// Output formatters: hand-rolled JSON (no serde dependency) and human
// summary that highlights the actionable findings first.

use std::fmt::Write as _;

use crate::breakout::BreakoutOutcome;
use crate::escalate::EscalateReport;
use crate::exploit::ExploitReport;
use crate::k8s::{K8sReport, ListSummary, RulesReview};
use crate::listener::ListenerReport;
use crate::pivot::PivotOutcome;
use crate::payload::PayloadReport;
use crate::recon::{
    Capabilities, KernelSurface, KubernetesContext, MountFindings, Namespaces, ReconResult,
    SecurityProfile,
};
use crate::signals::SignalReport;
use crate::vectors::VectorEval;
use crate::vuln_check::VulnReport;

pub fn recon_to_json(recon: &ReconResult) -> String {
    let mut out = String::with_capacity(2048);
    out.push('{');
    field(
        &mut out,
        "schema",
        &quoted("cornela-offsec.recon.v1"),
        false,
    );
    field(&mut out, "pid", &recon.pid.to_string(), true);
    field(&mut out, "uid", &option_u64(recon.uid), true);
    field(&mut out, "gid", &option_u64(recon.gid), true);
    field(
        &mut out,
        "comm",
        &option_string(recon.comm.as_deref()),
        true,
    );
    field(
        &mut out,
        "command_line",
        &option_string(recon.command_line.as_deref()),
        true,
    );
    field(
        &mut out,
        "capabilities",
        &capabilities_json(&recon.capabilities),
        true,
    );
    field(&mut out, "security", &security_json(&recon.security), true);
    field(
        &mut out,
        "namespaces",
        &namespaces_json(&recon.namespaces),
        true,
    );
    field(&mut out, "mounts", &mounts_json(&recon.mounts), true);
    field(&mut out, "kernel", &kernel_json(&recon.kernel), true);
    field(
        &mut out,
        "container",
        &container_json(&recon.container),
        true,
    );
    field(
        &mut out,
        "kubernetes",
        &kubernetes_json(&recon.kubernetes),
        true,
    );
    out.push('}');
    out
}

pub fn recon_to_human<W: std::io::Write>(recon: &ReconResult, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec recon ==");
    let _ = writeln!(w, "pid: {}", recon.pid);
    let _ = writeln!(
        w,
        "uid/gid: {} / {}",
        option_or(recon.uid),
        option_or(recon.gid)
    );
    if let Some(comm) = &recon.comm {
        let _ = writeln!(w, "comm: {comm}");
    }
    if let Some(cmd) = &recon.command_line {
        let _ = writeln!(w, "cmdline: {cmd}");
    }

    let _ = writeln!(w);
    let _ = writeln!(w, "[capabilities]");
    let _ = writeln!(
        w,
        "  effective:   {}",
        cap_hex(recon.capabilities.effective)
    );
    let _ = writeln!(
        w,
        "  permitted:   {}",
        cap_hex(recon.capabilities.permitted)
    );
    let _ = writeln!(w, "  bounding:    {}", cap_hex(recon.capabilities.bounding));
    let _ = writeln!(
        w,
        "  inheritable: {}",
        cap_hex(recon.capabilities.inheritable)
    );
    let _ = writeln!(w, "  ambient:     {}", cap_hex(recon.capabilities.ambient));

    let _ = writeln!(w);
    let _ = writeln!(w, "[security]");
    let _ = writeln!(
        w,
        "  seccomp_mode: {}",
        recon
            .security
            .seccomp_mode
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string())
    );
    let _ = writeln!(
        w,
        "  no_new_privs: {}",
        recon
            .security
            .no_new_privs
            .map(|v| v.to_string())
            .unwrap_or_else(|| "?".to_string())
    );
    let _ = writeln!(
        w,
        "  apparmor:     {}",
        recon.security.apparmor_profile.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        w,
        "  selinux:      {}",
        recon.security.selinux_context.as_deref().unwrap_or("none")
    );

    let _ = writeln!(w);
    let _ = writeln!(w, "[namespaces (vs PID 1)]");
    let _ = writeln!(w, "  pid:  shared={}", recon.namespaces.host_pid);
    let _ = writeln!(w, "  mnt:  shared={}", recon.namespaces.host_mnt);
    let _ = writeln!(w, "  net:  shared={}", recon.namespaces.host_net);
    let _ = writeln!(w, "  user: shared={}", recon.namespaces.host_user);
    let _ = writeln!(w, "  ipc:  shared={}", recon.namespaces.host_ipc);

    let _ = writeln!(w);
    let _ = writeln!(w, "[mounts]");
    if let Some(loc) = &recon.mounts.host_root_mounted {
        let _ = writeln!(w, "  HOST ROOT MOUNTED: {loc}");
    }
    if let Some(loc) = &recon.mounts.docker_socket {
        let _ = writeln!(w, "  docker.sock:       {loc}");
    }
    if let Some(loc) = &recon.mounts.containerd_socket {
        let _ = writeln!(w, "  containerd.sock:   {loc}");
    }
    if let Some(loc) = &recon.mounts.crio_socket {
        let _ = writeln!(w, "  crio.sock:         {loc}");
    }
    if let Some(loc) = &recon.mounts.kubelet_socket {
        let _ = writeln!(w, "  kubelet:           {loc}");
    }
    let _ = writeln!(w, "  /proc rw:          {}", recon.mounts.proc_writable);
    let _ = writeln!(w, "  /sys rw:           {}", recon.mounts.sys_writable);
    let _ = writeln!(
        w,
        "  cgroupfs rw:       {}",
        if recon.mounts.cgroupfs_writable_paths.is_empty() {
            "none".to_string()
        } else {
            recon.mounts.cgroupfs_writable_paths.join(", ")
        }
    );
    let _ = writeln!(
        w,
        "  /sys/kernel/debug: {}",
        recon.mounts.kernel_debug_mounted
    );
    if !recon.mounts.other_suspicious.is_empty() {
        let _ = writeln!(w, "  notable mounts:");
        for entry in &recon.mounts.other_suspicious {
            let _ = writeln!(w, "    - {entry}");
        }
    }

    let _ = writeln!(w);
    let _ = writeln!(w, "[kernel]");
    let _ = writeln!(
        w,
        "  release:           {}",
        recon.kernel.release.as_deref().unwrap_or("?")
    );
    let _ = writeln!(w, "  algif_aead loaded: {}", recon.kernel.algif_aead_loaded);
    let _ = writeln!(w, "  AF_ALG available:  {}", recon.kernel.af_alg_available);
    let _ = writeln!(w, "  /proc/kcore:       {}", recon.kernel.kcore_readable);
    let _ = writeln!(
        w,
        "  /proc/kallsyms:    {}",
        if recon.kernel.kallsyms_readable {
            "real addresses readable (kptr_restrict relaxed)"
        } else {
            "addresses zeroed or unreadable"
        }
    );
    let _ = writeln!(w, "  modules loaded:    {}", recon.kernel.modules_loaded);

    let _ = writeln!(w);
    let _ = writeln!(w, "[container]");
    let _ = writeln!(w, "  in_container:    {}", recon.container.in_container);
    if let Some(rt) = &recon.container.runtime_hint {
        let _ = writeln!(w, "  runtime_hint:    {rt}");
    }
    if let Some(id) = &recon.container.container_id {
        let _ = writeln!(w, "  container_id:    {id}");
    }
    if let Some(cg) = &recon.container.cgroup_path {
        let _ = writeln!(w, "  cgroup_path:     {cg}");
    }

    let _ = writeln!(w);
    let _ = writeln!(w, "[kubernetes]");
    let _ = writeln!(
        w,
        "  SA token:        {}",
        recon.kubernetes.service_account_token_present
    );
    if let Some(ns) = &recon.kubernetes.service_account_namespace {
        let _ = writeln!(w, "  namespace:       {ns}");
    }
    if let Some(host) = &recon.kubernetes.api_server_env {
        let port = recon
            .kubernetes
            .api_server_port_env
            .as_deref()
            .unwrap_or("?");
        let _ = writeln!(w, "  API server:      {host}:{port}");
    }
    let _ = writeln!(
        w,
        "  cluster.local in resolv.conf: {}",
        recon.kubernetes.kubelet_dns_in_resolv
    );
}

pub fn vectors_to_json(evals: &[VectorEval]) -> String {
    let mut out = String::with_capacity(2048);
    out.push('{');
    field(
        &mut out,
        "schema",
        &quoted("cornela-offsec.vectors.v1"),
        false,
    );
    out.push_str(",\"vectors\":[");
    for (idx, eval) in evals.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        field(&mut out, "id", &quoted(eval.id), false);
        field(&mut out, "name", &quoted(eval.name), true);
        field(&mut out, "category", &quoted(eval.category), true);
        field(
            &mut out,
            "severity_if_exploited",
            &quoted(eval.severity_if_exploited.as_str()),
            true,
        );
        field(&mut out, "applicable", &eval.applicable.to_string(), true);
        field(&mut out, "reasons", &string_array(&eval.reasons), true);
        field(
            &mut out,
            "manual_trigger",
            &quoted(eval.manual_trigger),
            true,
        );
        field(&mut out, "reference", &quoted(eval.reference), true);
        out.push('}');
    }
    out.push_str("]}");
    out
}

pub fn vectors_to_human<W: std::io::Write>(evals: &[VectorEval], w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec escape vector applicability ==");
    let _ = writeln!(w);

    let mut applicable: Vec<&VectorEval> = evals.iter().filter(|e| e.applicable).collect();
    let mut not_applicable: Vec<&VectorEval> = evals.iter().filter(|e| !e.applicable).collect();
    applicable.sort_by_key(|e| std::cmp::Reverse(e.severity_if_exploited));
    not_applicable.sort_by_key(|e| std::cmp::Reverse(e.severity_if_exploited));

    let _ = writeln!(w, "[applicable: {}]", applicable.len());
    for eval in &applicable {
        let _ = writeln!(
            w,
            "  [{}] {} ({})",
            eval.severity_if_exploited.as_str().to_uppercase(),
            eval.name,
            eval.id
        );
        for reason in &eval.reasons {
            let _ = writeln!(w, "    + {reason}");
        }
        let _ = writeln!(w, "    trigger: {}", eval.manual_trigger);
        let _ = writeln!(w, "    ref:     {}", eval.reference);
        let _ = writeln!(w);
    }

    let _ = writeln!(w, "[not applicable here: {}]", not_applicable.len());
    for eval in &not_applicable {
        let _ = writeln!(
            w,
            "  - [{}] {}",
            eval.severity_if_exploited.as_str(),
            eval.name
        );
        for reason in &eval.reasons {
            let _ = writeln!(w, "      reason: {reason}");
        }
    }
}

// ---- vuln-check ----

pub fn vuln_to_json(report: &VulnReport) -> String {
    let mut out = String::with_capacity(512);
    out.push('{');
    field(
        &mut out,
        "schema",
        &quoted("cornela-offsec.vuln-check.v1"),
        false,
    );
    field(&mut out, "cve", &quoted(&report.cve), true);
    field(&mut out, "name", &quoted(report.name), true);
    field(&mut out, "verdict", &quoted(report.verdict.as_str()), true);
    field(
        &mut out,
        "kernel_release",
        &option_string(report.kernel_release.as_deref()),
        true,
    );
    field(&mut out, "reasons", &string_array(&report.reasons), true);
    field(&mut out, "reference", &quoted(report.reference), true);
    out.push('}');
    out
}

pub fn vuln_to_human<W: std::io::Write>(report: &VulnReport, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec vuln-check ==");
    let _ = writeln!(w, "{}: {}", report.cve, report.name);
    let _ = writeln!(
        w,
        "verdict:        {}",
        report.verdict.as_str().to_uppercase()
    );
    let _ = writeln!(
        w,
        "kernel_release: {}",
        report.kernel_release.as_deref().unwrap_or("?")
    );
    let _ = writeln!(w);
    let _ = writeln!(w, "signals:");
    for reason in &report.reasons {
        let _ = writeln!(w, "  - {reason}");
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "reference: {}", report.reference);
}

// ---- signals ----

pub fn signals_to_json(report: &SignalReport) -> String {
    let mut out = String::with_capacity(256);
    out.push('{');
    field(
        &mut out,
        "schema",
        &quoted("cornela-offsec.signals.v1"),
        false,
    );
    field(&mut out, "pattern", &quoted(&report.pattern), true);
    field(&mut out, "iterations", &report.iterations.to_string(), true);
    field(
        &mut out,
        "events_fired",
        &report.events_fired.to_string(),
        true,
    );
    field(&mut out, "pid", &report.pid.to_string(), true);
    field(&mut out, "notes", &string_array(&report.notes), true);
    out.push('}');
    out
}

pub fn signals_to_human<W: std::io::Write>(report: &SignalReport, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec signals ==");
    let _ = writeln!(w, "pattern:       {}", report.pattern);
    let _ = writeln!(w, "iterations:    {}", report.iterations);
    let _ = writeln!(w, "events_fired:  {}", report.events_fired);
    let _ = writeln!(w, "pid:           {}", report.pid);
    if !report.notes.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "notes:");
        for note in &report.notes {
            let _ = writeln!(w, "  - {note}");
        }
    }
}

// ---- k8s ----

pub fn k8s_to_json(report: &K8sReport) -> String {
    let mut out = String::with_capacity(2048);
    out.push('{');
    field(&mut out, "schema", &quoted("cornela-offsec.k8s.v1"), false);
    field(&mut out, "in_cluster", &report.in_cluster.to_string(), true);
    field(
        &mut out,
        "api_server",
        &option_string(report.api_server.as_deref()),
        true,
    );
    field(
        &mut out,
        "service_account",
        &service_account_json(report.service_account.as_ref()),
        true,
    );
    field(
        &mut out,
        "permissions",
        &permissions_json(report.permissions.as_ref()),
        true,
    );
    field(
        &mut out,
        "namespace_secrets",
        &list_summary_json(report.namespace_secrets.as_ref()),
        true,
    );
    field(
        &mut out,
        "namespace_pods",
        &list_summary_json(report.namespace_pods.as_ref()),
        true,
    );
    field(&mut out, "notes", &string_array(&report.notes), true);
    out.push('}');
    out
}

pub fn k8s_to_human<W: std::io::Write>(report: &K8sReport, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec k8s recon ==");
    let _ = writeln!(w, "in_cluster: {}", report.in_cluster);
    if let Some(api) = &report.api_server {
        let _ = writeln!(w, "api_server: {api}");
    }
    if let Some(sa) = &report.service_account {
        let _ = writeln!(w);
        let _ = writeln!(w, "[service account]");
        let _ = writeln!(
            w,
            "  name:      {}",
            sa.service_account_name.as_deref().unwrap_or("?")
        );
        let _ = writeln!(
            w,
            "  namespace: {}",
            sa.service_account_namespace.as_deref().unwrap_or("?")
        );
        if !sa.audiences.is_empty() {
            let _ = writeln!(w, "  audiences: {}", sa.audiences.join(", "));
        }
        if let Some(exp) = sa.expiry_unix {
            let _ = writeln!(w, "  exp(unix): {exp}");
        }
    }
    if let Some(perms) = &report.permissions {
        let _ = writeln!(w);
        let _ = writeln!(
            w,
            "[permissions in own namespace] (incomplete={})",
            perms.incomplete
        );
        for rule in &perms.resource_rules {
            let _ = writeln!(w, "  + {rule}");
        }
        for rule in &perms.non_resource_rules {
            let _ = writeln!(w, "  + {rule}");
        }
    }
    write_list(w, "secrets in namespace", &report.namespace_secrets);
    write_list(w, "pods in namespace", &report.namespace_pods);
    if !report.notes.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[notes]");
        for note in &report.notes {
            let _ = writeln!(w, "  - {note}");
        }
    }
}

fn write_list<W: std::io::Write>(w: &mut W, label: &str, list: &Option<ListSummary>) {
    let Some(list) = list else {
        return;
    };
    let _ = writeln!(w);
    let _ = writeln!(w, "[{label}] (count={})", list.count);
    if let Some(err) = &list.error {
        let _ = writeln!(w, "  error: {err}");
        return;
    }
    for name in &list.names {
        let _ = writeln!(w, "  - {name}");
    }
}

fn service_account_json(claims: Option<&crate::k8s::JwtClaims>) -> String {
    let Some(claims) = claims else {
        return "null".to_string();
    };
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "raw_subject",
        &option_string(claims.raw_subject.as_deref()),
        false,
    );
    field(
        &mut out,
        "service_account_name",
        &option_string(claims.service_account_name.as_deref()),
        true,
    );
    field(
        &mut out,
        "service_account_namespace",
        &option_string(claims.service_account_namespace.as_deref()),
        true,
    );
    field(
        &mut out,
        "audiences",
        &string_array(&claims.audiences),
        true,
    );
    field(
        &mut out,
        "expiry_unix",
        &option_u64(claims.expiry_unix),
        true,
    );
    out.push('}');
    out
}

fn permissions_json(perms: Option<&RulesReview>) -> String {
    let Some(perms) = perms else {
        return "null".to_string();
    };
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "resource_rules",
        &string_array(&perms.resource_rules),
        false,
    );
    field(
        &mut out,
        "non_resource_rules",
        &string_array(&perms.non_resource_rules),
        true,
    );
    field(&mut out, "incomplete", &perms.incomplete.to_string(), true);
    out.push('}');
    out
}

fn list_summary_json(list: Option<&ListSummary>) -> String {
    let Some(list) = list else {
        return "null".to_string();
    };
    let mut out = String::new();
    out.push('{');
    field(&mut out, "kind", &quoted(list.kind), false);
    field(&mut out, "count", &list.count.to_string(), true);
    field(&mut out, "names", &string_array(&list.names), true);
    field(
        &mut out,
        "error",
        &option_string(list.error.as_deref()),
        true,
    );
    out.push('}');
    out
}

// ---- escalate ----

pub fn escalate_to_json(report: &EscalateReport) -> String {
    let mut out = String::with_capacity(2048);
    out.push('{');
    field(&mut out, "schema", &quoted("cornela-offsec.escalate.v1"), false);
    field(
        &mut out,
        "uid",
        &option_u64(report.uid.map(|v| v as u64)),
        true,
    );
    field(
        &mut out,
        "euid",
        &option_u64(report.euid.map(|v| v as u64)),
        true,
    );
    field(
        &mut out,
        "kernel_release",
        &option_string(report.kernel_release.as_deref()),
        true,
    );
    out.push_str(",\"findings\":[");
    for (idx, finding) in report.findings.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        field(&mut out, "id", &quoted(finding.id), false);
        field(&mut out, "title", &quoted(finding.title), true);
        field(&mut out, "severity", &quoted(finding.severity.as_str()), true);
        field(&mut out, "category", &quoted(finding.category), true);
        field(&mut out, "details", &string_array(&finding.details), true);
        out.push('}');
    }
    out.push_str("]}");
    out
}

pub fn escalate_to_human<W: std::io::Write>(report: &EscalateReport, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec escalate ==");
    let _ = writeln!(
        w,
        "uid/euid: {} / {}",
        option_or(report.uid.map(|v| v as u64)),
        option_or(report.euid.map(|v| v as u64))
    );
    let _ = writeln!(
        w,
        "kernel:   {}",
        report.kernel_release.as_deref().unwrap_or("?")
    );
    let _ = writeln!(w);
    if report.findings.is_empty() {
        let _ = writeln!(w, "no high-signal local privesc findings detected");
        return;
    }
    for finding in &report.findings {
        let _ = writeln!(
            w,
            "[{}] {} ({})",
            finding.severity.as_str().to_uppercase(),
            finding.title,
            finding.id
        );
        for detail in &finding.details {
            let _ = writeln!(w, "  - {detail}");
        }
        let _ = writeln!(w);
    }
}

// ---- exploit ----

pub fn exploit_to_json(report: &ExploitReport) -> String {
    let mut out = String::with_capacity(2048);
    out.push('{');
    field(&mut out, "schema", &quoted("cornela-offsec.exploit.v1"), false);
    field(&mut out, "poc_path", &quoted(&report.poc_path), true);
    field(&mut out, "poc_kind", &quoted(report.poc_kind.as_str()), true);
    field(
        &mut out,
        "target_cve",
        &option_string(report.target_cve.as_deref()),
        true,
    );
    field(&mut out, "executed", &report.executed.to_string(), true);
    field(&mut out, "timeout_secs", &report.timeout_secs.to_string(), true);
    field(&mut out, "timed_out", &report.timed_out.to_string(), true);
    field(
        &mut out,
        "exit_code",
        &option_i64(report.exit_code.map(|v| v as i64)),
        true,
    );
    field(&mut out, "duration_ms", &report.duration_ms.to_string(), true);
    field(&mut out, "verdict", &quoted(report.verdict.as_str()), true);
    field(&mut out, "pre", &observable_state_json(&report.pre), true);
    field(&mut out, "post", &observable_state_json(&report.post), true);
    field(&mut out, "stdout", &quoted(&report.stdout), true);
    field(&mut out, "stderr", &quoted(&report.stderr), true);
    field(&mut out, "reasons", &string_array(&report.reasons), true);
    out.push('}');
    out
}

pub fn exploit_to_human<W: std::io::Write>(report: &ExploitReport, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec exploit ==");
    let _ = writeln!(w, "poc:      {}", report.poc_path);
    let _ = writeln!(w, "kind:     {}", report.poc_kind.as_str());
    let _ = writeln!(w, "verdict:  {}", report.verdict.as_str().to_uppercase());
    let _ = writeln!(w, "executed: {}", report.executed);
    let _ = writeln!(w, "timeout:  {}s", report.timeout_secs);
    if let Some(cve) = &report.target_cve {
        let _ = writeln!(w, "target:   {cve}");
    }
    let _ = writeln!(w);
    let _ = writeln!(
        w,
        "pre:  uid={}; /etc/shadow={}; host_file={}",
        option_or(report.pre.uid.map(|v| v as u64)),
        report.pre.etc_shadow_readable,
        option_bool(report.pre.host_file_readable)
    );
    let _ = writeln!(
        w,
        "post: uid={}; /etc/shadow={}; host_file={}",
        option_or(report.post.uid.map(|v| v as u64)),
        report.post.etc_shadow_readable,
        option_bool(report.post.host_file_readable)
    );
    if !report.reasons.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[reasons]");
        for reason in &report.reasons {
            let _ = writeln!(w, "  - {reason}");
        }
    }
    if !report.stdout.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[stdout]");
        let _ = writeln!(w, "{}", report.stdout.trim_end());
    }
    if !report.stderr.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[stderr]");
        let _ = writeln!(w, "{}", report.stderr.trim_end());
    }
}

// ---- listener ----

pub fn listener_to_human<W: std::io::Write>(report: &ListenerReport, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec listener ==");
    let _ = writeln!(w, "bind:     {}", report.bind);
    let _ = writeln!(w, "port:     {}", report.port);
    let _ = writeln!(w, "kind:     {}", report.kind);
    let _ = writeln!(w, "once:     {}", report.once);
    let _ = writeln!(w, "sessions: {}", report.sessions);
    if let Some(err) = &report.error {
        let _ = writeln!(w, "error:    {err}");
    }
}

// ---- payload ----

pub fn payload_to_json(report: &PayloadReport) -> String {
    let mut out = String::with_capacity(512);
    out.push('{');
    field(&mut out, "schema", &quoted("cornela-offsec.payload.v1"), false);
    field(&mut out, "kind", &quoted(&report.kind), true);
    field(&mut out, "lang", &quoted(&report.lang), true);
    field(&mut out, "to", &quoted(&report.to), true);
    field(&mut out, "payload", &quoted(&report.payload), true);
    out.push('}');
    out
}

// ---- pivot ----

pub fn pivot_to_json(outcome: &PivotOutcome) -> String {
    let mut out = String::with_capacity(1024);
    out.push('{');
    field(&mut out, "schema", &quoted("cornela-offsec.pivot.v1"), false);
    field(&mut out, "technique", &quoted(outcome.plan.technique), true);
    field(&mut out, "category", &quoted(outcome.plan.category), true);
    field(&mut out, "command", &quoted(&outcome.plan.command), true);
    field(
        &mut out,
        "as_user",
        &option_string(outcome.plan.as_user.as_deref()),
        true,
    );
    field(
        &mut out,
        "target_container",
        &option_string(outcome.plan.target_container.as_deref()),
        true,
    );
    field(&mut out, "executed", &outcome.executed.to_string(), true);
    field(&mut out, "success", &outcome.success.to_string(), true);
    field(
        &mut out,
        "prerequisites",
        &pivot_prereqs_json(&outcome.plan.prerequisites),
        true,
    );
    field(&mut out, "steps", &string_array_static(outcome.plan.steps), true);
    field(&mut out, "stdout", &quoted(&outcome.stdout), true);
    field(&mut out, "stderr", &quoted(&outcome.stderr), true);
    field(&mut out, "notes", &string_array(&outcome.notes), true);
    field(&mut out, "reference", &quoted(outcome.plan.reference), true);
    out.push('}');
    out
}

pub fn pivot_to_human<W: std::io::Write>(outcome: &PivotOutcome, w: &mut W) {
    let _ = writeln!(w, "== cornela-offsec pivot: {} ==", outcome.plan.technique);
    let _ = writeln!(w, "category: {}", outcome.plan.category);
    let _ = writeln!(w, "command:  {}", outcome.plan.command);
    if let Some(as_user) = &outcome.plan.as_user {
        let _ = writeln!(w, "as_user:  {as_user}");
    }
    if let Some(container) = &outcome.plan.target_container {
        let _ = writeln!(w, "target:   {container}");
    }
    let _ = writeln!(w, "mode:     {}", if outcome.executed { "EXECUTED" } else { "dry-run" });
    let _ = writeln!(w);
    let _ = writeln!(w, "[prerequisites]");
    for prereq in &outcome.plan.prerequisites {
        let _ = writeln!(
            w,
            "  [{}] {}",
            if prereq.satisfied { "ok " } else { "MISS" },
            prereq.description
        );
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "[plan]");
    for step in outcome.plan.steps {
        let _ = writeln!(w, "  {step}");
    }
    if !outcome.stdout.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[stdout]");
        let _ = writeln!(w, "{}", outcome.stdout.trim_end());
    }
    if !outcome.stderr.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[stderr]");
        let _ = writeln!(w, "{}", outcome.stderr.trim_end());
    }
    if !outcome.notes.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[notes]");
        for note in &outcome.notes {
            let _ = writeln!(w, "  - {note}");
        }
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "ref: {}", outcome.plan.reference);
}

// ---- breakout ----

pub fn breakout_to_json(outcome: &BreakoutOutcome) -> String {
    let mut out = String::with_capacity(1024);
    out.push('{');
    field(
        &mut out,
        "schema",
        &quoted("cornela-offsec.breakout.v1"),
        false,
    );
    field(&mut out, "technique", &quoted(outcome.plan.technique), true);
    field(&mut out, "category", &quoted(outcome.plan.category), true);
    field(&mut out, "command", &quoted(&outcome.plan.command), true);
    field(&mut out, "executed", &outcome.executed.to_string(), true);
    field(&mut out, "success", &outcome.success.to_string(), true);
    field(
        &mut out,
        "prerequisites",
        &prereqs_json(&outcome.plan.prerequisites),
        true,
    );
    field(
        &mut out,
        "steps",
        &string_array_static(outcome.plan.steps),
        // (slice borrow is fine; steps is &'static [&'static str])
        true,
    );
    field(&mut out, "stdout", &quoted(&outcome.stdout), true);
    field(&mut out, "stderr", &quoted(&outcome.stderr), true);
    field(&mut out, "notes", &string_array(&outcome.notes), true);
    field(&mut out, "reference", &quoted(outcome.plan.reference), true);
    out.push('}');
    out
}

pub fn breakout_to_human<W: std::io::Write>(outcome: &BreakoutOutcome, w: &mut W) {
    let _ = writeln!(
        w,
        "== cornela-offsec breakout: {} ==",
        outcome.plan.technique
    );
    let _ = writeln!(w, "category:   {}", outcome.plan.category);
    let _ = writeln!(w, "command:    {}", outcome.plan.command);
    let _ = writeln!(
        w,
        "mode:       {}",
        if outcome.executed {
            "EXECUTED"
        } else {
            "dry-run"
        }
    );
    if outcome.executed {
        let _ = writeln!(
            w,
            "result:     {}",
            if outcome.success {
                "SUCCESS"
            } else {
                "FAILED / no observable output"
            }
        );
    }

    let _ = writeln!(w);
    let _ = writeln!(w, "[prerequisites]");
    for p in &outcome.plan.prerequisites {
        let mark = if p.satisfied { "ok " } else { "MISS" };
        let _ = writeln!(w, "  [{mark}] {}", p.description);
    }

    let _ = writeln!(w);
    let _ = writeln!(w, "[plan]");
    for step in outcome.plan.steps {
        let _ = writeln!(w, "  {step}");
    }

    if !outcome.stdout.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[stdout]");
        let _ = writeln!(w, "{}", outcome.stdout.trim_end());
    }
    if !outcome.stderr.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[stderr]");
        let _ = writeln!(w, "{}", outcome.stderr.trim_end());
    }
    if !outcome.notes.is_empty() {
        let _ = writeln!(w);
        let _ = writeln!(w, "[notes]");
        for note in &outcome.notes {
            let _ = writeln!(w, "  - {note}");
        }
    }
    let _ = writeln!(w);
    let _ = writeln!(w, "ref: {}", outcome.plan.reference);
}

fn prereqs_json(prereqs: &[crate::breakout::Prereq]) -> String {
    let mut out = String::from("[");
    for (idx, p) in prereqs.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        field(&mut out, "description", &quoted(&p.description), false);
        field(&mut out, "satisfied", &p.satisfied.to_string(), true);
        out.push('}');
    }
    out.push(']');
    out
}

fn string_array_static(values: &[&'static str]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&quoted(value));
    }
    out.push(']');
    out
}

fn pivot_prereqs_json(prereqs: &[crate::pivot::Prereq]) -> String {
    let mut out = String::from("[");
    for (idx, p) in prereqs.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push('{');
        field(&mut out, "description", &quoted(&p.description), false);
        field(&mut out, "satisfied", &p.satisfied.to_string(), true);
        out.push('}');
    }
    out.push(']');
    out
}

// ---- JSON primitives (hand-rolled to match parent crate's style) ----

fn field(out: &mut String, name: &str, value: &str, leading_comma: bool) {
    if leading_comma {
        out.push(',');
    }
    let _ = write!(out, "\"{name}\":{value}");
}

fn capabilities_json(c: &Capabilities) -> String {
    let mut out = String::new();
    out.push('{');
    field(&mut out, "effective", &option_hex(c.effective), false);
    field(&mut out, "permitted", &option_hex(c.permitted), true);
    field(&mut out, "bounding", &option_hex(c.bounding), true);
    field(&mut out, "inheritable", &option_hex(c.inheritable), true);
    field(&mut out, "ambient", &option_hex(c.ambient), true);
    out.push('}');
    out
}

fn observable_state_json(state: &crate::exploit::ObservableState) -> String {
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "uid",
        &option_u64(state.uid.map(|v| v as u64)),
        false,
    );
    field(
        &mut out,
        "hostname",
        &option_string(state.hostname.as_deref()),
        true,
    );
    field(
        &mut out,
        "etc_shadow_readable",
        &state.etc_shadow_readable.to_string(),
        true,
    );
    field(
        &mut out,
        "host_file_readable",
        &option_bool(state.host_file_readable),
        true,
    );
    out.push('}');
    out
}

fn security_json(s: &SecurityProfile) -> String {
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "seccomp_mode",
        &option_u64(s.seccomp_mode.map(|v| v as u64)),
        false,
    );
    field(&mut out, "no_new_privs", &option_bool(s.no_new_privs), true);
    field(
        &mut out,
        "apparmor_profile",
        &option_string(s.apparmor_profile.as_deref()),
        true,
    );
    field(
        &mut out,
        "apparmor_unconfined",
        &s.apparmor_unconfined.to_string(),
        true,
    );
    field(
        &mut out,
        "selinux_context",
        &option_string(s.selinux_context.as_deref()),
        true,
    );
    out.push('}');
    out
}

fn namespaces_json(n: &Namespaces) -> String {
    let mut out = String::new();
    out.push('{');
    field(&mut out, "pid", &option_string(n.pid.as_deref()), false);
    field(&mut out, "mnt", &option_string(n.mnt.as_deref()), true);
    field(&mut out, "net", &option_string(n.net.as_deref()), true);
    field(&mut out, "user", &option_string(n.user.as_deref()), true);
    field(&mut out, "uts", &option_string(n.uts.as_deref()), true);
    field(&mut out, "ipc", &option_string(n.ipc.as_deref()), true);
    field(&mut out, "host_pid", &n.host_pid.to_string(), true);
    field(&mut out, "host_mnt", &n.host_mnt.to_string(), true);
    field(&mut out, "host_net", &n.host_net.to_string(), true);
    field(&mut out, "host_user", &n.host_user.to_string(), true);
    field(&mut out, "host_ipc", &n.host_ipc.to_string(), true);
    out.push('}');
    out
}

fn mounts_json(m: &MountFindings) -> String {
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "host_root_mounted",
        &option_string(m.host_root_mounted.as_deref()),
        false,
    );
    field(
        &mut out,
        "docker_socket",
        &option_string(m.docker_socket.as_deref()),
        true,
    );
    field(
        &mut out,
        "containerd_socket",
        &option_string(m.containerd_socket.as_deref()),
        true,
    );
    field(
        &mut out,
        "crio_socket",
        &option_string(m.crio_socket.as_deref()),
        true,
    );
    field(
        &mut out,
        "kubelet_socket",
        &option_string(m.kubelet_socket.as_deref()),
        true,
    );
    field(
        &mut out,
        "proc_writable",
        &m.proc_writable.to_string(),
        true,
    );
    field(&mut out, "sys_writable", &m.sys_writable.to_string(), true);
    field(
        &mut out,
        "cgroupfs_writable_paths",
        &string_array(&m.cgroupfs_writable_paths),
        true,
    );
    field(
        &mut out,
        "kernel_debug_mounted",
        &m.kernel_debug_mounted.to_string(),
        true,
    );
    field(
        &mut out,
        "other_suspicious",
        &string_array(&m.other_suspicious),
        true,
    );
    out.push('}');
    out
}

fn kernel_json(k: &KernelSurface) -> String {
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "release",
        &option_string(k.release.as_deref()),
        false,
    );
    field(
        &mut out,
        "algif_aead_loaded",
        &k.algif_aead_loaded.to_string(),
        true,
    );
    field(
        &mut out,
        "af_alg_available",
        &k.af_alg_available.to_string(),
        true,
    );
    field(
        &mut out,
        "kcore_readable",
        &k.kcore_readable.to_string(),
        true,
    );
    field(
        &mut out,
        "kallsyms_readable",
        &k.kallsyms_readable.to_string(),
        true,
    );
    field(
        &mut out,
        "modules_loaded",
        &k.modules_loaded.to_string(),
        true,
    );
    out.push('}');
    out
}

fn container_json(c: &crate::recon::ContainerContext) -> String {
    let mut out = String::new();
    out.push('{');
    field(&mut out, "in_container", &c.in_container.to_string(), false);
    field(
        &mut out,
        "runtime_hint",
        &option_string(c.runtime_hint.as_deref()),
        true,
    );
    field(
        &mut out,
        "cgroup_path",
        &option_string(c.cgroup_path.as_deref()),
        true,
    );
    field(
        &mut out,
        "container_id",
        &option_string(c.container_id.as_deref()),
        true,
    );
    out.push('}');
    out
}

fn kubernetes_json(k: &KubernetesContext) -> String {
    let mut out = String::new();
    out.push('{');
    field(
        &mut out,
        "service_account_token_present",
        &k.service_account_token_present.to_string(),
        false,
    );
    field(
        &mut out,
        "service_account_namespace",
        &option_string(k.service_account_namespace.as_deref()),
        true,
    );
    field(
        &mut out,
        "api_server_env",
        &option_string(k.api_server_env.as_deref()),
        true,
    );
    field(
        &mut out,
        "api_server_port_env",
        &option_string(k.api_server_port_env.as_deref()),
        true,
    );
    field(
        &mut out,
        "kubelet_dns_in_resolv",
        &k.kubelet_dns_in_resolv.to_string(),
        true,
    );
    out.push('}');
    out
}

fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            ch if (ch as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", ch as u32);
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

fn string_array(values: &[String]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&quoted(value));
    }
    out.push(']');
    out
}

fn option_string(value: Option<&str>) -> String {
    value.map(quoted).unwrap_or_else(|| "null".to_string())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn option_i64(value: Option<i64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn option_hex(value: Option<u64>) -> String {
    value
        .map(|v| format!("\"{:016x}\"", v))
        .unwrap_or_else(|| "null".to_string())
}

fn option_bool(value: Option<bool>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn cap_hex(value: Option<u64>) -> String {
    value
        .map(|v| format!("0x{:016x}", v))
        .unwrap_or_else(|| "?".to_string())
}

fn option_or(value: Option<u64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "?".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::ReconResult;
    use crate::vectors::evaluate_all;

    #[test]
    fn recon_json_is_self_describing() {
        let json = recon_to_json(&ReconResult::default());
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"schema\":\"cornela-offsec.recon.v1\""));
        assert!(json.contains("\"capabilities\":{"));
        assert!(json.contains("\"namespaces\":{"));
    }

    #[test]
    fn vectors_json_contains_vector_array() {
        let evals = evaluate_all(&ReconResult::default());
        let json = vectors_to_json(&evals);
        assert!(json.contains("\"schema\":\"cornela-offsec.vectors.v1\""));
        assert!(json.contains("\"vectors\":["));
        assert!(json.contains("\"id\":\"cgroup_v1_release_agent\""));
    }

    #[test]
    fn quoted_escapes_control_chars() {
        assert_eq!(quoted("\x01"), "\"\\u0001\"");
        assert_eq!(quoted("a\nb"), "\"a\\nb\"");
    }

    #[test]
    fn human_recon_writes_sections() {
        let mut buf = Vec::new();
        recon_to_human(&ReconResult::default(), &mut buf);
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("[capabilities]"));
        assert!(text.contains("[security]"));
        assert!(text.contains("[namespaces"));
        assert!(text.contains("[kernel]"));
    }
}
