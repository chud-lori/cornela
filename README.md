# Cornela

Container Kernel Auditor for eBPF-based escape risk detection.

Cornela is a defensive Linux host and container audit tool for DevSecOps and blue teams. It audits host hardening signals, discovers container-like processes from cgroups, profiles Copy Fail-style exposure signals, and monitors suspicious runtime syscall sequences with eBPF.

Cornela is Linux-focused. On macOS, Docker Desktop containers run inside a Linux VM, so Cornela can only report that the local macOS host is not a supported kernel audit target.

## Install

End users should install from a published release. They do not need Rust, Cargo, Git, or the source tree.

After the repository is published, use this form:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install-release.sh | CORNELA_REPO=OWNER/REPO sh
```

For a non-root install prefix:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/scripts/install-release.sh | CORNELA_REPO=OWNER/REPO PREFIX="$HOME/.local" sh
```

Manual release install:

```bash
tar -xzf cornela-latest-x86_64-linux.tar.gz
cd cornela-*-linux
sudo ./install.sh
```

Then run:

```bash
cornela audit
cornela containers
cornela cve CVE-2026-31431
sudo cornela monitor --jsonl --max-events 20
```

## Usage

```bash
cornela audit
cornela audit --json
cornela containers
cornela containers --json
cornela cve CVE-2026-31431
cornela cve CVE-2026-31431 --json
cornela report --output report.json
cornela report --stdout
sudo cornela monitor --duration 30
sudo cornela monitor --events --duration 30
sudo cornela monitor --jsonl --max-events 20
sudo cornela monitor --jsonl --all-events --max-events 20
cornela monitor --simulate --json
```

Monitor output filters routine process execution and non-root UID-change noise by default. Use `--all-events` only when debugging raw tracepoint volume.

Use `--max-events` on busy servers to keep validation runs bounded.

## Release Builds

Maintainers build release artifacts on Linux because the `cornela` binary embeds the compiled eBPF object.

Preferred release flow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

The GitHub Actions release workflow builds, tests, packages, and uploads:

```text
cornela-0.1.0-x86_64-linux.tar.gz
cornela-0.1.0-x86_64-linux.tar.gz.sha256
cornela-latest-x86_64-linux.tar.gz
cornela-latest-x86_64-linux.tar.gz.sha256
```

Local Linux packaging is also supported:

```bash
sh scripts/package-release.sh
```

Development install from a source checkout:

```bash
sh scripts/install.sh
```

## Linux Requirements

Runtime monitoring must run on the Linux host or VM that owns the container kernel.

Install/build requirements:

- Linux
- Rust and Cargo, for maintainers only
- `clang` with BPF target support, for maintainers only
- libbpf/Linux headers, for maintainers only

Runtime requirements:

- root or sufficient BPF capabilities
- syscall tracepoints for `socket`, `splice`, process exec, and UID transitions
- kernel support for BPF ring buffers

Kernel BTF at `/sys/kernel/btf/vmlinux` is recommended for future CO-RE expansion, but Cornela currently uses a minimal local BPF header for the tracepoint structs it needs.

## Validation

Check the userspace detection pipeline without loading eBPF:

```bash
cornela monitor --simulate --events
cornela monitor --simulate --jsonl --max-events 2
```

Run live monitoring:

```bash
sudo cornela monitor --events --duration 30
sudo cornela monitor --jsonl --max-events 20
```

Safe lab trigger:

```bash
python3 scripts/safe_trigger_afalg_splice.py
```

Run the trigger in a separate shell while Cornela monitor is running. It generates benign AF_ALG and splice syscalls without exploit code.

## Why eBPF

eBPF lets defensive tools run small, verified programs at kernel hook points without changing kernel source code or loading traditional kernel modules.

Cornela uses eBPF because container escape signals often happen at the kernel boundary: syscalls, process execution, namespace context, cgroups, capabilities, and privilege transitions. With eBPF, Cornela can observe signals such as `socket(AF_ALG, ...)`, `splice()`, process exec, and UID transitions with lower overhead than polling process state from userspace.

The source directory is named `bpf/` instead of `ebpf/` because that is the common convention in Linux projects. The programs are modern eBPF programs, but they are still compiled as BPF bytecode and often live in a `bpf/` directory.

## Scope

- Host audit:
  - kernel version
  - loaded kernel modules
  - `algif_aead` presence
  - AF_ALG signal from `/proc/crypto`
  - seccomp, AppArmor, SELinux, and user namespace signals
  - common container runtime detection
- Container audit:
  - cgroup-based container-like process discovery
  - container ID/runtime hints
  - namespace identifiers
  - effective Linux capabilities
  - seccomp and `NoNewPrivs`
- Runtime monitor:
  - eBPF tracepoints for `socket`, `splice`, process exec, and UID transitions
  - ring buffer event ingestion
  - `/proc` event enrichment
  - high-signal event filtering
  - JSONL streaming for log pipelines
  - sequence correlation for `AF_ALG + splice`
  - critical correlation for `AF_ALG + splice + UID transition to root`
- CVE profile:
  - `CVE-2026-31431` Copy Fail exposure profile
  - kernel fixed-range heuristic
  - `algif_aead`, AF_ALG, seccomp, and container-context signals

## Non-Goals

- Cornela does not exploit vulnerabilities.
- Cornela does not prove a kernel is vulnerable.
- Cornela does not replace patching, seccomp, AppArmor, SELinux, gVisor, microVMs, or dedicated hosts.
