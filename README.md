# Cornela

Container Kernel Auditor for eBPF-based escape risk detection.

Cornela is a defensive Linux host and container audit tool. It checks host hardening signals, discovers container-like processes from cgroups, and produces explainable risk findings that help DevSecOps and blue teams harden shared-kernel container infrastructure.

The first implementation focuses on static auditing. Runtime eBPF monitoring is being built in small, testable layers.

## Why eBPF

eBPF is a Linux kernel technology that lets defensive tools run small, verified programs at kernel hook points without changing kernel source code or loading traditional kernel modules. Cornela uses eBPF because container escape signals often happen at the kernel boundary: syscalls, process execution, namespace context, cgroups, capabilities, and privilege transitions.

With eBPF, Cornela can observe suspicious runtime behavior such as `socket(AF_ALG, ...)`, `splice()`, setuid execution, and container-scoped syscall sequences with lower overhead than polling process state from userspace.

The source directory is named `bpf/` instead of `ebpf/` because that is the common convention in Linux projects. The programs are modern eBPF programs, but they are still compiled as BPF bytecode and often live in a `bpf/` directory.

## Commands

```bash
cargo run -- audit
cargo run -- audit --json
cargo run -- containers
cargo run -- cve CVE-2026-31431
cargo run -- cve CVE-2026-31431 --json
cargo run -- report --output report.json
cargo run -- report --stdout
cargo run -- monitor
cargo run -- monitor --json --duration 30
```

## Install

From the repository root:

```bash
cargo install --path .
```

Then run:

```bash
cornela audit
cornela audit --json
cornela containers
cornela cve CVE-2026-31431
cornela report --output report.json
cornela report --stdout
```

Cornela is designed to audit Linux container hosts. On macOS, Docker Desktop containers run inside a Linux VM, so Cornela can only report that the local macOS host is not a supported kernel audit target.

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
  - hardening recommendations in reports
  - report metadata and container risk summaries for lab comparisons
- Runtime monitor foundation:
  - stable event schema
  - monitor readiness/preflight output
  - initial eBPF tracepoint source for `socket`, `splice`, and process exec
- CVE profile scanning:
  - `CVE-2026-31431` Copy Fail exposure profile
  - kernel fixed-range heuristic
  - `algif_aead`, `AF_ALG`, seccomp, and container-context signals
  - defensive recommendations without exploit execution

## Project Status

- Phase 1, static host audit: implemented
- Phase 2, basic eBPF event monitor: eBPF source and CLI preflight implemented; userspace loader planned
- Phase 3, container metadata enrichment: planned
- Phase 4, risk engine expansion: reusable assessment helper and recommendations implemented
- Phase 5, research evaluation: planned

## Non-Goals

- Cornela does not exploit vulnerabilities.
- Cornela does not prove a kernel is vulnerable.
- Cornela does not replace patching, seccomp, AppArmor, SELinux, gVisor, microVMs, or dedicated hosts.
