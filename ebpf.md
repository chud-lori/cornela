# KernelSentry: eBPF Container Escape Risk Auditor

## Inspiration

KernelSentry is inspired by Copy Fail (`CVE-2026-31431`), a Linux kernel local privilege escalation issue that created serious concern for shared-kernel container environments. The issue is important for container security research because it shows that a bug in a host kernel subsystem can become a container escape risk when untrusted workloads share the same kernel.

Copy Fail is not the only problem this tool should care about. It is the first case study and detection profile. The broader goal is to build a reusable eBPF audit framework for observing container behavior that may indicate kernel escape primitives.

## Project Summary

KernelSentry is a defensive eBPF-based audit tool for detecting container escape risk patterns on Linux hosts. The first research target is Copy Fail (`CVE-2026-31431`)-style risk, where a container or untrusted local process may abuse shared-kernel behavior through primitives such as `AF_ALG`, `splice()`, setuid binaries, and unexpected privilege transitions.

This project is not an exploit tool. It is an audit and monitoring tool for defenders, students, and researchers who want to understand whether a host/container environment is exposed to dangerous kernel-local privilege escalation patterns.

## Recommended Stack

- eBPF program: C
- Userspace loader and CLI: Rust
- eBPF loader library: `libbpf-rs` or `aya`
- CLI parsing: `clap`
- JSON output: `serde` and `serde_json`
- Container metadata: Docker/containerd/Kubernetes inspection through `/proc`, cgroups, and optional runtime sockets

This split keeps the kernel-side code close to standard eBPF practice while using Rust for safer userspace logic, reporting, and CLI development.

## Why This Project Is Useful

Containers are often treated as a security boundary, but they share the host kernel unless they run inside a stronger isolation layer such as a microVM or user-space kernel. Kernel local privilege escalation bugs can therefore become container escape risks.

KernelSentry focuses on visibility:

- Which containers can create risky kernel interfaces?
- Which processes are using suspicious syscall combinations?
- Is the host hardened against known container escape primitives?
- Are untrusted workloads running with weak isolation?

## Initial Scope

The MVP should audit and monitor these areas:

1. Host hardening status
2. Container runtime configuration
3. Suspicious syscall activity
4. Privilege transition events
5. Risk scoring and JSON reporting

## MVP Features

### 1. Host Audit

Collect host-level facts:

- Kernel version
- Whether `algif_aead` is loaded
- Whether `AF_ALG` appears usable
- Whether common container runtimes are present
- Whether user namespaces are enabled
- Whether AppArmor/SELinux/seccomp appear active

Example output:

```text
Host Audit
Kernel: 6.x.x
algif_aead: loaded
seccomp: available
container runtime: docker
risk: medium
```

### 2. Container Audit

For each detected container, collect:

- Container ID
- Process IDs
- Cgroup path
- Runtime name if available
- Privileged mode if detectable
- Seccomp profile status if detectable
- Dangerous Linux capabilities if detectable

Important risk signals:

- privileged container
- host PID namespace
- host filesystem mounts
- missing seccomp profile
- dangerous capabilities such as `CAP_SYS_ADMIN`
- untrusted workload running on a shared kernel

### 3. Runtime eBPF Monitoring

Attach eBPF programs to tracepoints/kprobes for:

- `sys_enter_socket`
- `sys_enter_splice`
- `sched_process_exec`
- UID/GID transition signals where practical

Initial suspicious patterns:

- process creates `socket(AF_ALG, ...)`
- process calls `splice()`
- process executes `/usr/bin/su`, `/bin/su`, `sudo`, or another setuid target
- non-root process unexpectedly becomes UID 0
- suspicious syscall sequence occurs inside a container

### 4. Event Enrichment

Userspace Rust code should enrich raw eBPF events with:

- PID
- PPID if available
- UID/GID
- process name
- command line
- namespace identifiers
- cgroup path
- container ID if available
- timestamp

Example event:

```json
{
  "type": "suspicious_syscall",
  "severity": "high",
  "pid": 18422,
  "uid": 1000,
  "comm": "python3",
  "container_id": "7d9f...",
  "syscall": "socket",
  "details": {
    "family": "AF_ALG"
  }
}
```

### 5. Risk Scoring

The tool should produce simple, explainable scores:

- Low: hardened host, no suspicious activity
- Medium: risky kernel/module/config exists but no suspicious runtime activity
- High: risky config plus suspicious syscall behavior
- Critical: privilege transition or likely escape sequence observed

Example:

```text
Container: ci-runner-42
Risk: HIGH
Reasons:
- seccomp profile does not appear to block AF_ALG
- algif_aead module is loaded on host
- container process created AF_ALG socket
- container process called splice()
```

## Suggested CLI

```bash
kernelsentry audit
kernelsentry monitor
kernelsentry monitor --json
kernelsentry report --output report.json
kernelsentry containers
```

## Suggested Repository Structure

```text
kernelsentry/
  bpf/
    monitor.bpf.c
    vmlinux.h
  src/
    main.rs
    audit.rs
    container.rs
    event.rs
    monitor.rs
    report.rs
    risk.rs
  Cargo.toml
  build.rs
  README.md
```

## Development Phases

### Phase 1: Static Host Audit

Build the Rust CLI and implement host checks:

- kernel version
- loaded modules
- seccomp availability
- container runtime detection
- JSON report output

Deliverable:

```bash
kernelsentry audit
```

### Phase 2: Basic eBPF Event Monitor

Add eBPF tracepoints for:

- process execution
- `socket()` calls
- `splice()` calls

Deliverable:

```bash
kernelsentry monitor
```

### Phase 3: Container Awareness

Map events to containers using:

- `/proc/<pid>/cgroup`
- namespace identifiers
- Docker/containerd metadata where available

Deliverable:

```bash
kernelsentry containers
kernelsentry monitor --containers
```

### Phase 4: Risk Engine

Add rules that combine static audit data and runtime events.

Example rule:

```text
IF algif_aead is loaded
AND a container process creates AF_ALG socket
AND the same process calls splice()
THEN risk = high
```

Deliverable:

```bash
kernelsentry report --output report.json
```

### Phase 5: Research Evaluation

Test the tool against safe lab scenarios:

- normal Docker container
- container with default seccomp
- container with seccomp disabled
- privileged container
- CI-runner-like container
- patched vs unpatched kernel, if a legal lab is available

Do not run public exploits on production systems.

## Research Questions

The project can answer:

- Can eBPF detect container behavior associated with kernel escape primitives?
- Which container configurations expose the largest risk?
- How useful is syscall sequence monitoring for early warning?
- Can a lightweight local tool produce actionable container hardening recommendations?

## Non-Goals

- Do not publish or embed exploit code.
- Do not attempt automatic kernel exploitation.
- Do not claim to fully prevent container escapes.
- Do not replace patching, seccomp, gVisor, microVMs, or dedicated hosts.

## Better Future Extensions

- Generate recommended seccomp profiles
- Kubernetes admission controller mode
- Prometheus metrics exporter
- TUI dashboard
- Tetragon-compatible event format
- GitHub Actions or GitLab Runner audit profile
- AI sandbox audit profile

## Final Name

Use **KernelSentry**.

Reason:

- It clearly communicates kernel-level monitoring.
- It sounds defensive, not exploit-focused.
- It is broad enough for future eBPF security features.
- It is easier to present than a CVE-specific name.
