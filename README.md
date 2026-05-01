# Cornela

Container Kernel Auditor for eBPF-based escape risk detection.

Cornela is a defensive Linux host and container audit tool. It checks host hardening signals, discovers container-like processes from cgroups, and produces explainable risk findings that help DevSecOps and blue teams harden shared-kernel container infrastructure.

The first implementation focuses on static auditing. Runtime eBPF monitoring is planned next.

## Commands

```bash
cargo run -- audit
cargo run -- audit --json
cargo run -- containers
cargo run -- report --output report.json
cargo run -- monitor
```

## Current Scope

- Host audit:
  - kernel version
  - loaded kernel modules
  - `algif_aead` presence
  - seccomp availability
  - AppArmor and SELinux signals
  - user namespace status
  - common container runtime detection
- Container audit:
  - process IDs
  - cgroup paths
  - container ID hints
  - namespace identifiers
  - effective Linux capabilities
  - risky capability flags
- Risk scoring:
  - low, medium, high, critical
  - explainable reasons in text and JSON output

## Non-Goals

- Cornela does not exploit vulnerabilities.
- Cornela does not prove a kernel is vulnerable.
- Cornela does not replace patching, seccomp, AppArmor, SELinux, gVisor, microVMs, or dedicated hosts.
