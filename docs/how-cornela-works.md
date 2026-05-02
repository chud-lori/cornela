# How Cornela Works

Cornela is a Linux container kernel auditor. It looks at the host, the running container-like processes, and selected live kernel events to help engineers find shared-kernel risk.

This document explains the low-level pieces in practical terms.

## The Core Problem

Containers are isolated processes, but they usually share the same Linux kernel as the host. If a container is too privileged, can reach dangerous host interfaces, or triggers suspicious kernel behavior, the risk is not limited to the application inside that container.

Cornela focuses on these questions:

- What kernel and container hardening signals are present on this server?
- Which running containers look risky from the host's point of view?
- Are any processes using syscall patterns associated with escape primitives?
- Which finding should an engineer investigate first?

Cornela does not prove exploitation. It reports defensive risk signals.

## Static Audit Path

The static audit reads Linux state from host interfaces such as:

- `/proc/version` and kernel release data
- loaded module signals
- `/proc/crypto`
- `/proc/<pid>/status`
- `/proc/<pid>/cgroup`
- `/proc/<pid>/ns/*`
- `/proc/<pid>/mountinfo`
- Linux security module indicators for AppArmor and SELinux

This gives Cornela a host and container view without needing to talk to every application.

## Container Discovery

Cornela does not ask Docker for the main list of containers first. It starts from `/proc`, because `/proc` is what the Linux host actually sees.

For each process, Cornela reads:

- cgroup path
- process ID
- parent process ID
- UID/GID
- process name
- command line
- namespace identifiers
- capability mask
- seccomp mode
- `NoNewPrivs`
- mount information

Then it groups processes that appear to belong to the same container ID.

When Docker is available, Cornela also attempts `docker inspect` for extra hints such as:

- privileged mode
- host PID namespace
- host network namespace
- seccomp setting
- configured capabilities

If Docker inspection is not available, Cornela still reports the `/proc`-based view.

## What Namespaces Mean

Linux namespaces decide which parts of the system a process sees.

Important examples:

- PID namespace: whether the process sees host processes or only container-local processes.
- Mount namespace: whether the process has an isolated filesystem mount view.
- Network namespace: whether the process shares host networking.
- User namespace: whether user and group IDs are mapped separately.

If a container shares host namespaces, isolation is weaker. Cornela marks that as a risk signal.

## What Capabilities Mean

Linux capabilities split root privileges into smaller pieces.

Some capabilities are especially risky for containers:

- `CAP_SYS_ADMIN`: broad administrative power, often close to root-equivalent.
- `CAP_SYS_MODULE`: load or unload kernel modules.
- `CAP_SYS_PTRACE`: inspect or manipulate other processes.
- `CAP_NET_ADMIN`: control networking.

Cornela reads the effective capability mask from `/proc/<pid>/status` and reports dangerous capability bits.

## What Seccomp and NoNewPrivs Mean

Seccomp can restrict which syscalls a process is allowed to make. It is one of the most important container hardening layers.

`NoNewPrivs` prevents a process and its children from gaining new privileges through exec transitions. If it is not set, Cornela reports that as a hardening gap.

Cornela reports these values because they directly affect how much damage a compromised container process can attempt at the kernel boundary.

## Why eBPF

eBPF lets Cornela attach small verified programs to kernel tracepoints. A tracepoint is a stable place where the kernel can expose an event, such as "a process entered this syscall."

Cornela uses eBPF for live monitoring because many escape-risk signals happen at syscall time:

- process creates an AF_ALG socket
- process calls `splice`
- process changes UID/GID
- process enters namespace or mount syscalls
- process attempts BPF or module-loading syscalls
- process opens selected privileged host paths

The eBPF program sends compact events to userspace through a ring buffer. Userspace then enriches the event with `/proc` metadata.

## Runtime Probes

Cornela currently monitors these syscall families:

- AF_ALG socket creation: `socket(AF_ALG, ...)`
- data movement: `splice`
- process execution: `sched_process_exec`
- UID transitions: `setuid`, `setreuid`, `setresuid`
- GID transitions: `setgid`, `setregid`, `setresgid`
- namespace activity: `unshare`, `setns`, `clone3`
- mount activity: `mount`, `move_mount`, `open_tree`, `fsopen`
- BPF activity: `bpf`
- capability changes: `capset`
- module activity: `init_module`, `finit_module`, `delete_module`
- keyring activity: `keyctl`, `add_key`, `request_key`
- selected privileged file access: `openat` for Docker socket and kernel control paths

Some probes are optional because kernel support differs by distro and version. If an optional tracepoint is unavailable, Cornela reports that it was skipped instead of failing the entire monitor.

## Sequence Tracking

Cornela does not treat every single syscall as an incident. It tracks short sequences by process and container context.

Examples:

```text
socket(AF_ALG) + splice()
```

This is high signal for Copy Fail-style investigation.

```text
socket(AF_ALG) + splice() + UID transition to root
```

This is critical because the suspicious syscall chain is followed by a root UID transition.

```text
namespace change + mount attempt
```

This is high because namespace and mount operations are common building blocks in container boundary manipulation.

Some events are high-signal by themselves:

- `bpf` syscall attempt
- kernel module load/unload attempt
- capability change attempt
- opening Docker socket or selected kernel control paths

These do not prove exploitation, but they are worth immediate review when seen from a container or untrusted process.

## Event Enrichment

The eBPF side intentionally sends small events. It captures things like:

- timestamp
- event type
- PID
- UID/GID
- syscall argument
- short process name
- optional path text for selected `openat` events

Userspace enriches the event with:

- command line
- parent PID
- cgroup path
- container ID
- namespace IDs
- container runtime hints

This split keeps kernel-side code small and lets Rust userspace do heavier parsing safely.

## Risk Levels

Cornela uses simple risk levels:

- Low: no meaningful risk signal found.
- Medium: hardening gap or suspicious context.
- High: risky configuration or suspicious runtime behavior.
- Critical: strong escape-risk chain or kernel-control attempt.

Risk is a prioritization tool, not a legal or forensic conclusion.

## Output Modes

Human-readable:

```bash
cornela audit
cornela containers
sudo cornela monitor --events --duration 30
```

JSON:

```bash
cornela audit --json
cornela containers --json
cornela cve CVE-2026-31431 --json
```

JSONL:

```bash
sudo cornela monitor --jsonl --max-events 100
```

JSON and JSONL are the real integration surfaces for logs, CI, dashboards, and other security tooling.

## What Cornela Does Not Do

Cornela does not:

- exploit vulnerabilities
- prove a kernel is vulnerable
- block syscalls
- modify containers
- replace patching or runtime hardening
- replace AppArmor, SELinux, seccomp, gVisor, microVMs, or dedicated hosts

It helps engineers see and prioritize container kernel risk.
