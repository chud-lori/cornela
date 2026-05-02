# Copy Fail Demo Guide

This guide explains CVE-2026-31431, why it matters for container hosts, and how to demonstrate Cornela detection safely.

The audience is a regular engineer, DevOps engineer, or platform owner. You do not need kernel exploitation experience to follow it.

## What Copy Fail Is

Copy Fail, tracked as CVE-2026-31431, is a Linux kernel local privilege escalation issue in the kernel crypto API path. Public reporting describes it as a reliable bug affecting many Linux distributions and as especially important for shared-kernel container environments.

The important idea is this:

```text
An unprivileged process can interact with a kernel crypto interface in a way that may let the kernel write where it should not.
```

That is dangerous because the write target can be backed by the Linux page cache.

## Why Containers Are Involved

A normal Docker or containerd container is not a small virtual machine. It is a group of Linux processes using isolation features such as namespaces, cgroups, capabilities, seccomp, and mount rules.

Most containers still share the host kernel.

That means:

- the host and containers run on the same kernel
- kernel bugs are not contained by the container boundary
- the host page cache can be shared across host and container activity
- a kernel local privilege escalation can become a container escape risk

This is why Cornela treats kernel exposure as infrastructure risk, not just application risk.

## Kubernetes Attack Architecture

The Kubernetes impact is easier to understand as an architecture problem, not just a kernel bug.

Public Kubernetes PoC writeups describe three roles:

- Attacker workload: an unprivileged pod controlled by the attacker.
- Shared kernel page cache: host kernel memory used to cache file contents from container image layers.
- Privileged workload: a trusted system pod, such as a privileged node agent or networking DaemonSet, that later executes a binary from the same shared image layer.

The defensive model looks like this:

```text
┌──────────────────────────┐       ┌──────────────────────────┐
│ Untrusted Pod            │       │ Privileged System Pod     │
│ unprivileged process     │       │ node-level permissions    │
│                          │       │                          │
│ AF_ALG + splice pattern  │       │ later executes a cached   │
│ touches kernel crypto    │       │ binary from shared layer  │
└─────────────┬────────────┘       └─────────────┬────────────┘
              │                                  │
              ▼                                  ▼
        ┌──────────────────────────────────────────────┐
        │ Shared Host Kernel + Page Cache              │
        │ same cached file pages can be observed by    │
        │ multiple containers using shared image layers │
        └──────────────────────────────────────────────┘
```

The important lesson is that the untrusted pod and the privileged pod do not need to communicate over the network. The shared kernel and shared page-cache state become the bridge.

In real exploitation, the attacker would try to corrupt cached bytes for a file that a privileged workload later executes. Cornela does not reproduce that. Cornela watches for the kernel-boundary behavior and host/container conditions that make this attack architecture plausible.

## The Building Blocks

Copy Fail involves Linux features that are easy to misunderstand, so here is the plain-language version.

### AF_ALG

`AF_ALG` is a Linux socket family for using kernel crypto algorithms from userspace.

Most engineers know sockets as network objects. `AF_ALG` is also a socket interface, but instead of connecting to another machine, userspace connects to kernel crypto operations such as hashing or encryption.

In simple terms:

```text
userspace process -> AF_ALG socket -> Linux kernel crypto code
```

### splice

`splice()` is a Linux syscall for moving data between file descriptors without copying the data through a normal userspace buffer.

That can be useful for performance, but it also means data movement is happening through lower-level kernel paths.

In simple terms:

```text
file or pipe data -> splice() -> another kernel-backed destination
```

### Page Cache

The page cache is memory the Linux kernel uses to cache file contents.

When a process reads a file, Linux may keep the file's contents in memory so future reads are faster. Many processes, containers, and host services may observe the same cached file pages because the cache belongs to the shared kernel.

If a bug allows a process to write into page-cache-backed memory that should be read-only, the effect can cross boundaries.

## How The Exploit Works At A High Level

This section explains the exploit concept for defenders. It intentionally avoids weaponized steps, payload offsets, target modifications, or code that performs a real privilege escalation.

The public description of Copy Fail places the bug in the kernel crypto API, specifically around an in-place optimization in an AEAD path.

At a high level, the exploit shape is:

```text
1. Open a kernel crypto operation through AF_ALG.
2. Arrange data movement so file-backed page-cache memory reaches that crypto path.
3. Use splice() as part of that data movement.
4. Trigger a vulnerable path where the kernel treats a page-cache-backed page as writable output.
5. Cause a small unintended write into cached file data.
6. Turn that write primitive into privilege escalation by targeting security-sensitive file content.
```

The key bug class is not "crypto is broken." The cryptographic algorithm is not the main point. The problem is memory ownership and write permissions: whether the kernel should ever write through a memory page that came from a read-only file-backed cache path.

The result is comparable in spirit to Dirty Pipe: the exploit primitive is a small write into something that should not be writable by the attacker.

## End-To-End Attack Chain

For a defender, the full Copy Fail container-escape story can be summarized in three stages.

### 1. Page-Cache Corruption

An unprivileged process reaches the kernel crypto API through `AF_ALG`, uses `splice()`, and triggers the vulnerable copy/write path. The dangerous result is a write into page-cache-backed file data that the process should not be able to modify.

Cornela coverage:

- `cornela cve CVE-2026-31431` checks exposure signals.
- `cornela audit` reports AF_ALG/kernel crypto exposure.
- `cornela monitor` watches for `socket(AF_ALG)` plus `splice()`.

### 2. Cross-Container Propagation

Container runtimes commonly use overlay filesystems and shared image layers. If two containers use the same image layer, the kernel may serve their reads from the same cached pages.

That means a page-cache corruption from one container can be visible when another container reads or executes the same cached file.

Cornela coverage:

- `cornela containers` shows container-like process groups.
- `cornela audit` reports runtime and container hardening context.
- Runtime events are enriched with cgroup and container ID when available.

### 3. Privileged Execution

The most serious case is when the second reader is a privileged system workload, such as a node-level agent, networking component, CI runner helper, or privileged DaemonSet. If that trusted component executes corrupted cached bytes, the impact can move from "unprivileged container process" to "node-level execution."

Cornela coverage:

- detects privileged containers, host namespaces, broad capabilities, and risky mounts
- reports containers with Docker socket access or weak hardening
- raises severity when suspicious runtime behavior is followed by UID/capability changes

## Why Shared Image Layers Matter

Image layers are a storage optimization. If many containers use the same base image, the runtime does not need to store every file separately for every container. The same lower layer can be reused.

That optimization is normally good. For Copy Fail-style issues, it becomes part of the threat model:

```text
same image layer
same file content
same host page cache
different containers observing the effect
```

This is why a bug in the kernel can cross what looks like an application boundary. The container filesystem view is isolated, but the kernel cache behind that view is shared.

## Why A Small Write Can Be Serious

A few bytes may not sound dangerous. In kernel exploitation, a small reliable write can be enough if the target is carefully chosen.

Attackers often look for places where a small change can affect trust decisions, execution flow, or privilege boundaries. Public reporting describes Copy Fail as capable of local privilege escalation and container escape under affected conditions.

For defenders, the exact payload is less important than the exposure model:

```text
Can an untrusted process reach AF_ALG?
Can it use splice?
Is the host kernel affected?
Is the process inside a shared-kernel container?
Are seccomp and hardening controls blocking the path?
```

Those are the questions Cornela is built to help answer.

## What Cornela Detects

Cornela does not need to run exploit code. It watches for the syscall sequence and environment signals that make this class of issue relevant.

Static audit checks include:

- kernel version and release information
- kernel crypto exposure signals such as `/proc/crypto`
- AF_ALG-related availability signals
- seccomp availability
- AppArmor and SELinux signals
- detected container runtimes
- container isolation and mount risks
- privileged container and host namespace signals when runtime metadata is available
- Docker socket, host root, `/proc`, and `/sys` mount risk

Live eBPF monitoring checks include:

- `socket(AF_ALG, ...)`
- `splice()`
- UID/GID transitions
- capability changes
- namespace and mount activity
- BPF syscall attempts
- module load or unload attempts
- keyring activity

Cornela then correlates events by process and container context.

For Copy Fail-style behavior, the main high-signal chain is:

```text
socket(AF_ALG) + splice()
```

If the process later transitions to root in the same short window, Cornela raises severity:

```text
socket(AF_ALG) + splice() + UID transition to root
```

This does not prove exploitation. It tells the engineer, "This process is touching the same kernel boundary shape used by this vulnerability class. Investigate it."

## Cornela Signal Map

| Attack architecture area | What can go wrong | Cornela signal |
| --- | --- | --- |
| Host kernel | affected kernel or exposed crypto API | `cornela audit`, `cornela cve CVE-2026-31431` |
| Untrusted pod/container | process reaches vulnerable syscall shape | `socket(AF_ALG)` plus `splice()` sequence |
| Shared-kernel boundary | container is not a VM and shares kernel state | container discovery, namespace IDs, cgroup context |
| Privileged system workload | system pod has node-level power | privileged mode, host namespaces, broad capabilities |
| Dangerous mounts | container can control host or runtime | Docker socket, host root, writable `/proc` or `/sys` |
| Post-signal escalation | UID/capability/module/keyring activity follows | sequence findings and high-signal event types |

## Safe Demo

Cornela includes a harmless script that generates the detection signals without exploiting the kernel.

The script does not:

- escape a container
- become root
- write into the host page cache
- patch a setuid binary
- modify host files
- exploit CVE-2026-31431

It only:

- creates an AF_ALG hash socket
- calls `splice()` into `/dev/null`
- optionally calls `setuid(getuid())`, which does not change privilege

### Terminal 1: Run Cornela Monitor

```bash
sudo cornela monitor --events --duration 30
```

### Terminal 2: Run The Harmless Demo

From the repository:

```bash
python3 scripts/demo_copy_fail_signals.py
```

Expected script output:

```text
Cornela Copy Fail signal demo
mode: harmless syscall signal generation
escape attempted: no
privilege escalation attempted: no
host file modification attempted: no
signal: AF_ALG socket created
signal: splice called
done: Cornela should report AF_ALG + splice correlation
```

Expected Cornela finding:

```text
process used AF_ALG and splice within the Copy Fail correlation window
```

## Safe Container Demo

To show why this matters for containers, run the same harmless signal generator inside a disposable container.

From the repository directory:

```bash
docker run --rm -v "$PWD/scripts:/scripts:ro" python:3.12-slim python /scripts/demo_copy_fail_signals.py
```

Keep Cornela running on the host in another terminal:

```bash
sudo cornela monitor --events --duration 30
```

What this demonstrates:

- a process inside a container can still reach host kernel syscalls
- Cornela can enrich events with container context when the process is detected through cgroups
- the detection does not depend on running a real exploit
- the same monitoring path works for a Kubernetes pod because pods are still Linux processes on the node

What this does not demonstrate:

- actual container escape
- root compromise
- file overwrite
- proof that the host is vulnerable
- shared image layer corruption
- privileged DaemonSet execution

## How To Explain The Demo

A good short explanation for an audience:

```text
Copy Fail is dangerous because containers share the host kernel. The vulnerable shape involves AF_ALG, splice, and a page-cache-backed write path inside the kernel crypto API. Cornela watches for that shape using eBPF. In this demo we are not exploiting the server; we are safely generating the same syscall signals so defenders can verify that monitoring and enrichment work.
```

Then show:

```bash
cornela audit
cornela cve CVE-2026-31431
sudo cornela monitor --events --duration 30
python3 scripts/demo_copy_fail_signals.py
```

For a Kubernetes-oriented talk, describe the real-world path like this:

```text
An untrusted pod can hit the host kernel because containers share the kernel.
Copy Fail-style exploitation abuses AF_ALG and splice to affect cached file pages.
If another privileged pod later executes bytes from the same shared image layer,
the impact can become node-level execution. Cornela helps defenders see the
kernel exposure, risky container configuration, and live syscall sequence before
they rely only on post-compromise evidence.
```

## Interpreting Results

If `cornela audit` reports high risk, look at the reasons first.

Common examples:

- AF_ALG or kernel crypto API exposed
- kernel version falls inside the affected heuristic range
- containers detected on the host
- seccomp is missing or weak
- a container has risky mounts such as Docker socket
- a container runs with broad capabilities
- `NoNewPrivs` is not set

If `cornela monitor` reports the AF_ALG plus `splice` sequence, ask:

- Which process did it?
- Was it inside a container?
- Was the workload expected to use kernel crypto APIs?
- Did it happen with UID, capability, namespace, or mount activity?
- Is this process trusted?
- Can seccomp block AF_ALG for this workload?

## Recommended Defenses

For Copy Fail-style exposure, prioritize:

- patch the kernel to a vendor-fixed build
- apply distro security updates
- use seccomp to block unnecessary `AF_ALG` socket creation
- avoid running untrusted code on shared-kernel container hosts
- use microVMs, dedicated hosts, or stronger isolation for untrusted tenants
- remove Docker socket mounts from application containers
- avoid privileged containers
- drop unnecessary Linux capabilities
- enable `NoNewPrivs` where practical
- keep AppArmor or SELinux enabled

Cornela helps you find where to start, but patching and hardening are still required.

## Source

Public background used for this explanation:

- Bugcrowd: https://www.bugcrowd.com/blog/what-we-know-about-copy-fail-cve-2026-31431/
- Percivalll Kubernetes PoC README: https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC
