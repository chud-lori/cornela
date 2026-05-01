# Cornela

Container Kernel Auditor for eBPF-based escape risk detection.

Cornela is a defensive Linux host and container audit tool. It checks host hardening signals, discovers container-like processes from cgroups, and produces explainable risk findings that help DevSecOps and blue teams harden shared-kernel container infrastructure.

Cornela combines static audit checks with a live eBPF monitor for suspicious container escape risk patterns.

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
cargo run -- monitor --events --duration 10
cargo run -- monitor --jsonl --duration 30
cargo run -- monitor --jsonl --max-events 20
cargo run -- monitor --jsonl --all-events --max-events 20
cargo run -- monitor --json --duration 30
cargo run -- monitor --simulate --json
```

## Install

For development from the repository root:

```bash
cargo install --path .
```

For a Linux server install with the embedded eBPF program bundled into one release binary:

```bash
sh scripts/install.sh
```

That installs `cornela` to `/usr/local/bin` by default. Override the prefix if needed:

```bash
PREFIX="$HOME/.local" sh scripts/install.sh
```

Then run without `cargo`:

```bash
cornela audit
cornela audit --json
cornela containers
cornela cve CVE-2026-31431
cornela report --output report.json
cornela report --stdout
sudo cornela monitor --jsonl --max-events 20
sudo cornela monitor --events --duration 30
```

To build a distributable archive on a Linux build host:

```bash
sh scripts/package-release.sh
```

The archive is written under `dist/` and contains the `cornela` binary, a binary-only installer, README, handover notes, and the safe lab trigger script. Build the package on Linux because the release binary embeds the compiled eBPF object for the target kernel platform.

End users do not need to clone the repository or install Rust when they receive the release archive:

```bash
tar -xzf cornela-0.1.0-x86_64-linux.tar.gz
cd cornela-0.1.0-x86_64-linux
sudo ./install.sh
sudo cornela monitor --jsonl --max-events 20
```

For a non-root prefix:

```bash
PREFIX="$HOME/.local" ./install.sh
```

Cornela is designed to audit Linux container hosts. On macOS, Docker Desktop containers run inside a Linux VM, so Cornela can only report that the local macOS host is not a supported kernel audit target.

## Linux eBPF Requirements

Live monitoring requires running Cornela on the Linux host or VM that owns the container kernel. The eBPF loader path expects:

- root or sufficient BPF capabilities
- `clang` with BPF target support
- libbpf headers available to compile `bpf/monitor.bpf.c`
- tracepoints for `sys_enter_socket`, `sys_enter_splice`, and `sched_process_exec`

Kernel BTF at `/sys/kernel/btf/vmlinux` is recommended for future CO-RE expansion, but the initial tracepoint program includes a minimal local header for the structs it uses.

On non-Linux systems, `cornela monitor` reports preflight status only.

Useful Linux server checks:

```bash
cargo run -- monitor --simulate
sudo cargo run -- monitor --duration 30
sudo cargo run -- monitor --events --duration 10
sudo cargo run -- monitor --jsonl --duration 30
sudo cargo run -- monitor --jsonl --max-events 20
sudo cargo run -- monitor --jsonl --all-events --max-events 20
sudo cargo run -- monitor --json --duration 30
```

Use `--simulate` first to verify Cornela's userspace event pipeline before loading eBPF programs.
Use `--events` to include captured enriched events in the final output, and `--jsonl` to stream one JSON object per event/finding for log pipelines.
Monitor output filters routine exec and non-root UID-change noise by default. Use `--all-events` when debugging raw tracepoint volume.
Use `--max-events` as a server-safe guard when validating event-heavy hosts.

Safe event trigger for lab validation:

```bash
python3 scripts/safe_trigger_afalg_splice.py
```

Run that in a separate shell while Cornela monitor is running. It generates benign AF_ALG and splice syscalls without exploit code.

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
  - `/proc` event enrichment for process, cgroup, container, and namespace context
  - syscall sequence correlation for `AF_ALG` plus `splice`
  - critical sequence correlation for `AF_ALG` plus `splice` plus UID transition to root
  - Linux-only Aya loader path for the eBPF ring buffer
  - monitor readiness/preflight output
  - eBPF tracepoint source for `socket`, `splice`, process exec, and UID transition syscalls
  - default event filtering for high-signal runtime output
  - `--all-events` raw tracepoint mode for debugging
- CVE profile scanning:
  - `CVE-2026-31431` Copy Fail exposure profile
  - kernel fixed-range heuristic
  - `algif_aead`, `AF_ALG`, seccomp, and container-context signals
  - defensive recommendations without exploit execution

## Project Status

Cornela is ready as a v0.1 defensive auditor/monitor for Linux validation and lab use. The main remaining work after validation is deeper Docker/containerd socket inspection for configured privileged mode, named seccomp profile, host mounts, and configured capability sets.

## Non-Goals

- Cornela does not exploit vulnerabilities.
- Cornela does not prove a kernel is vulnerable.
- Cornela does not replace patching, seccomp, AppArmor, SELinux, gVisor, microVMs, or dedicated hosts.
