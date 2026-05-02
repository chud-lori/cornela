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

## Container Escape Risk Model

Copy Fail is easier to understand as a shared-kernel risk model, not only as a single kernel bug.

There are three defensive ideas:

- Untrusted workload: any process you do not fully trust, such as an app container, CI job, sandbox, or tenant workload.
- Shared kernel state: the host kernel and page cache used behind container filesystem views.
- Higher-privilege workload: a host process or trusted container with broader access than the original workload.

The model looks like this:

```text
┌──────────────────────────┐       ┌──────────────────────────┐
│ Untrusted Workload       │       │ Trusted Workload         │
│ app, CI job, sandbox     │       │ host agent, runner,      │
│ or tenant container      │       │ privileged container     │
│                          │       │                          │
│ AF_ALG + splice pattern  │       │ later executes a cached   │
│ touches kernel crypto    │       │ file or binary            │
└─────────────┬────────────┘       └─────────────┬────────────┘
              │                                  │
              ▼                                  ▼
        ┌──────────────────────────────────────────────┐
        │ Shared Host Kernel + Page Cache              │
        │ cached file pages can be observed through    │
        │ different process/container filesystem views │
        └──────────────────────────────────────────────┘
```

The important lesson is that two workloads do not need to communicate over the network for kernel state to matter. If they share the same host kernel, kernel bugs can cross boundaries that look separate at the container level.

Kubernetes is one common place where this model matters because nodes run both application pods and privileged system components. The same idea can apply to Docker hosts, CI runners, AI code sandboxes, and any platform that runs untrusted code on a shared Linux kernel.

Cornela does not reproduce exploitation. It watches for the kernel-boundary behavior and host/container conditions that make this risk model relevant.

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

## Low-Level Mechanics For Defenders

Public PoC code for Copy Fail is usually organized around a small corruption primitive. Cornela does not include that primitive, but defenders should understand what the primitive is doing so they know why Cornela watches the syscalls it watches.

At a low level, the exploit path has these parts:

### 1. Read-Only Target File Descriptor

The PoC opens a target file read-only. The file may be a binary or another file whose cached contents can matter later.

The important detail is that the attacker does not need a normal writable file descriptor. The risk comes from making the kernel write through a path that should have remained read-only from the attacker's point of view.

Cornela relevance:

- static audit checks whether risky container and kernel conditions exist
- live monitoring focuses on the later syscall sequence, because opening a read-only file is common and noisy

### 2. AF_ALG AEAD Socket Pair

The PoC creates an `AF_ALG` socket for a kernel crypto operation, binds it to an AEAD algorithm, configures crypto options, and accepts a data socket.

For regular engineers, think of this as:

```text
control socket: configure the kernel crypto operation
data socket: send data into that configured operation
```

The specific algorithm and key material are exploit implementation details. For Cornela, the defensive signal is that an untrusted process reached the kernel crypto API through `AF_ALG`.

Cornela relevance:

- `cornela cve CVE-2026-31431` checks whether AF_ALG/kernel crypto exposure appears present
- `cornela monitor` emits an `af_alg_socket` event when it sees `socket(AF_ALG, ...)`

### 3. Initial Crypto Message

The PoC sends an initial message and control metadata to the AF_ALG data socket. In exploit code, this sets up the crypto operation so more data can follow.

This step matters because the vulnerable behavior is tied to how the kernel crypto path handles input and output buffers, not because the attacker cares about the encrypted result.

Cornela relevance:

- Cornela does not parse crypto control messages
- Cornela intentionally stays at the syscall and sequence layer to avoid fragile, exploit-specific parsing

### 4. Pipe As A Data-Movement Bridge

The PoC creates a pipe. Pipes are common Linux file descriptors used to move bytes between kernel paths.

In this exploit shape, the pipe acts as a bridge:

```text
target file -> pipe -> AF_ALG data socket
```

The pipe is not suspicious by itself. The signal becomes important when combined with `splice()` and `AF_ALG`.

Cornela relevance:

- Cornela does not alert on every pipe
- Cornela correlates the higher-signal `AF_ALG` and `splice()` behavior

### 5. splice From File Into Pipe

The PoC uses `splice()` to move bytes from the read-only target file descriptor into the pipe.

This is important because `splice()` can move data through kernel-managed buffers instead of copying it through a normal userspace buffer.

Cornela relevance:

- `cornela monitor` emits a `splice` event when the syscall is observed
- by itself, `splice()` may be normal for some workloads

### 6. splice From Pipe Into AF_ALG Socket

The PoC then uses `splice()` again, moving the pipe data into the accepted AF_ALG data socket.

This is the high-signal part for defenders:

```text
read-only file-backed data
  -> pipe
  -> AF_ALG crypto socket
```

That combination is why Cornela tracks `socket(AF_ALG)` and `splice()` as a sequence instead of treating either syscall alone as proof of compromise.

Cornela relevance:

- `socket(AF_ALG) + splice()` inside the correlation window produces a Copy Fail-style sequence finding
- if the process is inside a container, userspace enrichment attempts to attach container/cgroup context

### 7. Drain Or Complete The Crypto Operation

The PoC reads from the AF_ALG data socket to complete the kernel operation. Public exploit descriptions connect this completion path to the vulnerable in-place write behavior.

For defenders, the key point is not the output bytes. The key point is that completing the crypto operation can cause the vulnerable kernel path to act on memory it should not modify.

Cornela relevance:

- Cornela does not need to observe the final read to catch the main suspicious shape
- the important monitored sequence has already happened before the operation completes

### 8. Repeated Small Windows

Public PoCs usually repeat the primitive in small chunks. This is because the write primitive is limited and must be applied carefully.

That repetition can create multiple `AF_ALG` and `splice()` events from the same process over a short period.

Cornela relevance:

- repeated events from the same PID or container should be treated as stronger investigation evidence
- JSONL output is useful here because it preserves each event for later timeline review

## Mapping Public PoC Functions To Cornela Signals

This table describes the defensive meaning of common PoC components without providing runnable exploit code.

| PoC component | Defensive meaning | Cornela view |
| --- | --- | --- |
| Open target file read-only | attacker does not need normal write permission | context, not usually an alert |
| Create AF_ALG socket | process reaches kernel crypto API | `af_alg_socket` event |
| Configure AEAD operation | vulnerable crypto path may be reachable | covered by AF_ALG exposure signal |
| Create pipe | bridge for kernel data movement | context, not usually an alert |
| `splice(file -> pipe)` | file-backed data enters kernel pipe path | `splice` event |
| `splice(pipe -> AF_ALG)` | pipe data enters kernel crypto socket | correlated with AF_ALG |
| Complete/read crypto output | vulnerable operation completes | not required for Cornela sequence finding |
| Repeat small chunks | primitive is applied repeatedly | repeated events in monitor timeline |

The practical detection rule is:

```text
One isolated syscall is weak evidence.
AF_ALG plus splice from the same process/container is strong investigation signal.
AF_ALG plus splice plus privilege, capability, namespace, or mount activity is higher risk.
```

## End-To-End Attack Chain

For a defender, the Copy Fail risk story can be summarized in three stages.

### 1. Page-Cache Corruption

An unprivileged process reaches the kernel crypto API through `AF_ALG`, uses `splice()`, and triggers the vulnerable copy/write path. The dangerous result is a write into page-cache-backed file data that the process should not be able to modify.

Cornela coverage:

- `cornela cve CVE-2026-31431` checks exposure signals.
- `cornela audit` reports AF_ALG/kernel crypto exposure.
- `cornela monitor` watches for `socket(AF_ALG)` plus `splice()`.

### 2. Cross-Boundary Visibility

Container runtimes commonly use overlay filesystems, cached file pages, and reused image content. If two workloads read the same underlying file content, the kernel may serve those reads from shared cached pages.

That means a page-cache corruption from one workload can become visible when another workload reads or executes the same cached content.

Cornela coverage:

- `cornela containers` shows container-like process groups.
- `cornela audit` reports runtime and container hardening context.
- Runtime events are enriched with cgroup and container ID when available.

### 3. Privileged Execution

The most serious case is when the second reader is a privileged or trusted workload, such as a host agent, CI runner helper, node component, or privileged container. If that trusted component executes corrupted cached bytes, the impact can move from "unprivileged process" to "higher-privilege execution."

Cornela coverage:

- detects privileged containers, host namespaces, broad capabilities, and risky mounts
- reports containers with Docker socket access or weak hardening
- raises severity when suspicious runtime behavior is followed by UID/capability changes

## Why Shared Cached Content Matters

Linux caches file contents in memory. Container runtimes also reuse filesystem content through image layers and overlay filesystems. These are normal performance and storage optimizations.

For Copy Fail-style issues, those optimizations become part of the threat model:

```text
same file content
same host page cache
different workloads observing the effect
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
| Untrusted workload | process reaches vulnerable syscall shape | `socket(AF_ALG)` plus `splice()` sequence |
| Shared-kernel boundary | container is not a VM and shares kernel state | container discovery, namespace IDs, cgroup context |
| Higher-privilege workload | trusted process or container has broader power | privileged mode, host namespaces, broad capabilities |
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
- the same monitoring path can apply to a Kubernetes pod because pods are still Linux processes on the node

What this does not demonstrate:

- actual container escape
- root compromise
- file overwrite
- proof that the host is vulnerable
- shared page-cache corruption
- Kubernetes-specific privileged workload execution

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

For a container-platform talk, describe the real-world path like this:

```text
An untrusted container can hit the host kernel because containers share the kernel.
Copy Fail-style exploitation abuses AF_ALG and splice to affect cached file pages.
If another trusted process or privileged container later reads or executes those
cached bytes, the impact can move across the container boundary. Cornela helps
defenders see the kernel exposure, risky container configuration, and live
syscall sequence before they rely only on post-compromise evidence.
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
