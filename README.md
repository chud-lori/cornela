# Cornela

Experimental Container Kernel Auditor for eBPF-based escape risk detection.

Cornela helps engineers audit Linux container servers for shared-kernel escape risk. It checks host hardening, discovers container-like processes, profiles kernel exposure signals, and can watch live syscall sequences with eBPF.

Status: alpha. Cornela is ready for public testing and defensive lab use, but it should not be treated as a mature production security product yet.

## Why This Tool Exists

Containers share the host kernel. That means a weak host configuration, an exposed kernel feature, an over-privileged container, or a suspicious syscall chain can become infrastructure risk, even when the application code looks fine.

Cornela exists to answer practical security questions:

- Is this Linux server hardened enough for container workloads?
- Are container-like processes running with risky capabilities or weak isolation?
- Are kernel features related to known escape paths exposed?
- Do live runtime events show suspicious escape-like behavior?
- What should an engineer fix first?

Cornela is for defensive auditing, DevSecOps checks, blue-team validation, and server hardening. It does not exploit vulnerabilities.

## What It Solves

Container security is often split across too many places: kernel version, loaded modules, cgroups, namespaces, capabilities, seccomp, LSM status, runtime metadata, and live syscall behavior. Cornela brings those signals into one command-line tool and returns explainable findings instead of raw kernel noise.

It helps with:

- hardening Linux container hosts before production use
- checking whether container isolation is weaker than expected
- spotting risky kernel exposure signals such as AF_ALG availability
- detecting suspicious runtime sequences such as `AF_ALG + splice`
- producing JSON/JSONL output for logs, CI, or security pipelines
- giving engineers concrete remediation direction

## How Cornela Works

Cornela combines static audit signals with live kernel telemetry.

1. It reads host security state from Linux system interfaces such as `/proc`, cgroups, namespaces, loaded module signals, seccomp status, and LSM indicators.
2. It groups container-like processes by cgroup and enriches them with process, namespace, capability, seccomp, and `NoNewPrivs` context.
3. It profiles kernel exposure signals relevant to container escape risk, including the Copy Fail profile and AF_ALG-related indicators.
4. When live monitoring is enabled, it loads a small eBPF program that listens to selected syscall tracepoints.
5. Userspace enriches each kernel event with container/process metadata, filters routine noise, and tracks suspicious sequences over a short time window.
6. Cornela reports findings with severity, reason, affected process/container context, and machine-readable output when requested.

The important part is correlation. Cornela does not alert just because one syscall happened. It looks for meaningful chains, such as a process using AF_ALG and `splice()` close together, then raises the severity if that activity is followed by a root UID transition.

## Install

Install from a published release. Users do not need Rust, Cargo, Git, or the source tree.

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/cornela/main/scripts/install-release.sh | sh
```

For a non-root install prefix:

```bash
curl -fsSL https://raw.githubusercontent.com/chud-lori/cornela/main/scripts/install-release.sh | PREFIX="$HOME/.local" sh
```

Manual install from a downloaded release archive:

```bash
tar -xzf cornela-latest-x86_64-linux.tar.gz
cd cornela-*-linux
sudo ./install.sh
```

Release files are published at:

```text
https://github.com/chud-lori/cornela/releases
```

## Quick Start

Run a host and container audit:

```bash
cornela audit
```

List detected container-like process groups:

```bash
cornela containers
```

Check the Copy Fail exposure profile:

```bash
cornela cve CVE-2026-31431
```

Run the live eBPF monitor:

```bash
sudo cornela monitor --events --duration 30
```

Stream high-signal runtime events as JSONL:

```bash
sudo cornela monitor --jsonl --max-events 20
```

Print hardening profiles and integration templates:

```bash
cornela profile seccomp
cornela profile kubernetes-admission
cornela profile prometheus
cornela profile tetragon
cornela profile github-runner
cornela profile gitlab-runner
cornela profile ai-sandbox
```

## Common Workflows

Generate a JSON report:

```bash
cornela report --output cornela-report.json
```

Send audit output to another tool:

```bash
cornela audit --json
```

Run a bounded live check on a busy server:

```bash
sudo cornela monitor --jsonl --max-events 50
```

Debug raw tracepoint volume:

```bash
sudo cornela monitor --jsonl --all-events --max-events 50
```

`--all-events` is intentionally noisy. Normal monitor output filters routine process execution and non-root UID-change events so engineers see higher-signal activity first.

## How Cornela Helps Secure a Server

Cornela turns low-level Linux/container signals into an audit view engineers can act on.

- Host hardening: reports kernel, module, seccomp, AppArmor, SELinux, user namespace, and runtime signals.
- Container isolation: detects container-like cgroups, namespace context, effective capabilities, seccomp mode, and `NoNewPrivs`.
- Runtime configuration: reports Docker privileged mode, host namespace settings, configured seccomp hints, configured capabilities, and risky host mounts when detectable.
- Kernel exposure: profiles Copy Fail-relevant signals such as `algif_aead`, AF_ALG, and kernel version ranges.
- Runtime detection: uses eBPF tracepoints to observe suspicious syscall sequences without exploit code.
- Hardening templates: prints seccomp, Kubernetes admission, metrics, event-format, runner, and AI sandbox guidance for common operational environments.
- Prioritization: assigns risk levels and explains why a finding matters.

Typical remediation after a Cornela finding may include patching the kernel, removing risky capabilities, enabling seccomp, enabling AppArmor/SELinux, disabling unnecessary kernel features, avoiding host namespaces, or moving risky workloads to stronger isolation.

## Runtime Detection

Cornela tracks syscall sequences, not just isolated syscalls.

Current high-signal sequence:

```text
socket(AF_ALG) + splice()
```

Higher-risk sequence:

```text
socket(AF_ALG) + splice() + UID transition to root
```

These patterns are treated as defensive escape-risk signals. A finding does not prove exploitation; it tells engineers where to investigate and harden.

## Requirements

Cornela is designed for Linux container hosts.

Runtime monitoring requires:

- Linux
- root or sufficient BPF capabilities
- kernel support for BPF ring buffers
- syscall tracepoints for `socket`, `splice`, process exec, and UID transitions
- optional syscall tracepoints for GID transitions

On macOS, Docker Desktop runs containers inside a Linux VM. Run Cornela inside the Linux VM or on the real Linux server, not on the macOS host.

## Output Formats

Human-readable output:

```bash
cornela audit
sudo cornela monitor --events --duration 30
```

JSON output:

```bash
cornela audit --json
cornela containers --json
cornela cve CVE-2026-31431 --json
```

JSONL stream for log pipelines:

```bash
sudo cornela monitor --jsonl --max-events 20
```

## Safety Model

Cornela is an auditor and monitor.

- It does not exploit vulnerabilities.
- It does not run proof-of-concept exploit code.
- It does not modify containers.
- It does not replace kernel patching or container hardening.
- It helps engineers find and prioritize shared-kernel risk.

## License

Apache-2.0. See `LICENSE`.
