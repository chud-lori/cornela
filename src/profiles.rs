pub const PROFILE_NAMES: &[&str] = &[
    "seccomp",
    "kubernetes-admission",
    "prometheus",
    "tetragon",
    "github-runner",
    "gitlab-runner",
    "ai-sandbox",
];

pub fn render(name: &str) -> Result<&'static str, String> {
    match name {
        "seccomp" => Ok(SECCOMP_PROFILE),
        "kubernetes-admission" => Ok(KUBERNETES_ADMISSION_POLICY),
        "prometheus" => Ok(PROMETHEUS_METRICS_EXAMPLE),
        "tetragon" => Ok(TETRAGON_EVENT_SCHEMA),
        "github-runner" => Ok(GITHUB_RUNNER_PROFILE),
        "gitlab-runner" => Ok(GITLAB_RUNNER_PROFILE),
        "ai-sandbox" => Ok(AI_SANDBOX_PROFILE),
        _ => Err(format!(
            "unknown profile: {name}; available profiles: {}",
            PROFILE_NAMES.join(", ")
        )),
    }
}

const SECCOMP_PROFILE: &str = r#"{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_AARCH64"
  ],
  "syscalls": [
    {
      "names": ["socket"],
      "action": "SCMP_ACT_ERRNO",
      "args": [
        {
          "index": 0,
          "value": 38,
          "op": "SCMP_CMP_EQ"
        }
      ],
      "comment": "Block AF_ALG socket creation for untrusted containers."
    }
  ]
}
"#;

const KUBERNETES_ADMISSION_POLICY: &str = r#"apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: cornela-container-hardening
spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
  validations:
    - expression: "!object.spec.hostPID"
      message: "Cornela policy: hostPID is not allowed."
    - expression: "!object.spec.hostNetwork"
      message: "Cornela policy: hostNetwork is not allowed."
    - expression: "object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.privileged) || c.securityContext.privileged != true)"
      message: "Cornela policy: privileged containers are not allowed."
    - expression: "object.spec.containers.all(c, !has(c.securityContext) || !has(c.securityContext.allowPrivilegeEscalation) || c.securityContext.allowPrivilegeEscalation != true)"
      message: "Cornela policy: privilege escalation is not allowed."
"#;

const PROMETHEUS_METRICS_EXAMPLE: &str = r#"# HELP cornela_container_risk Container risk score where low=1, medium=2, high=3, critical=4.
# TYPE cornela_container_risk gauge
cornela_container_risk{container_id="example",risk="high"} 3
# HELP cornela_runtime_findings_total Runtime sequence findings observed by Cornela.
# TYPE cornela_runtime_findings_total counter
cornela_runtime_findings_total{severity="high",type="af_alg_splice"} 0
"#;

const TETRAGON_EVENT_SCHEMA: &str = r#"{
  "process": {
    "pid": "{{pid}}",
    "binary": "{{comm}}",
    "arguments": "{{command_line}}"
  },
  "container": {
    "id": "{{container_id}}"
  },
  "event": {
    "source": "cornela",
    "type": "{{type}}",
    "severity": "{{severity}}",
    "detail": "{{detail}}"
  }
}
"#;

const GITHUB_RUNNER_PROFILE: &str = r#"# Cornela GitHub Actions runner hardening profile
- Run untrusted jobs on dedicated ephemeral Linux runners.
- Avoid privileged Docker jobs unless the repository is trusted.
- Do not mount /var/run/docker.sock into job containers.
- Keep seccomp enabled for service containers.
- Drop CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, and CAP_NET_ADMIN unless required.
- Run `cornela audit --json` before admitting a runner image to production.
- Run `sudo cornela monitor --jsonl --max-events 50` during risky job validation.
"#;

const GITLAB_RUNNER_PROFILE: &str = r#"# Cornela GitLab Runner hardening profile
- Prefer isolated runners for untrusted projects.
- Avoid privileged Docker executor mode for shared runners.
- Do not expose the host Docker socket to job containers.
- Keep seccomp/AppArmor enabled.
- Drop high-risk capabilities by default.
- Run `cornela audit --json` during runner host validation.
- Run `sudo cornela monitor --jsonl --max-events 50` during executor testing.
"#;

const AI_SANDBOX_PROFILE: &str = r#"# Cornela AI sandbox hardening profile
- Run model/tool sandboxes on dedicated Linux hosts or microVMs.
- Avoid host PID, host network, and host mount namespaces.
- Do not mount Docker/containerd sockets into sandbox containers.
- Block unnecessary AF_ALG socket creation with seccomp.
- Drop CAP_SYS_ADMIN, CAP_SYS_MODULE, CAP_SYS_PTRACE, and CAP_NET_ADMIN.
- Treat `AF_ALG + splice` runtime findings as high-priority investigation signals.
- Treat `AF_ALG + splice + UID transition to root` as critical.
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_known_profiles() {
        for profile in PROFILE_NAMES {
            assert!(render(profile).is_ok());
        }
    }

    #[test]
    fn rejects_unknown_profile() {
        assert!(render("unknown").is_err());
    }
}
