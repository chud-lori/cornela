// SPDX-License-Identifier: Apache-2.0
//
// Cornela runtime monitor eBPF program.
//
// This source defines Cornela's probe targets and event payload shape. Keep
// field sizes stable so JSON/event handling remains compatible.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AF_ALG 38
#define CLONE_NEWNS 0x00020000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWUTS 0x04000000
#define CLONE_NEWIPC 0x08000000
#define CLONE_NEWUSER 0x10000000
#define CLONE_NEWPID 0x20000000
#define CLONE_NEWNET 0x40000000

#define CORNELA_NAMESPACE_FLAGS (CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET)

enum cornela_event_type {
    CORNELA_EVENT_AF_ALG_SOCKET = 1,
    CORNELA_EVENT_SPLICE = 2,
    CORNELA_EVENT_PROCESS_EXEC = 3,
    CORNELA_EVENT_UID_TRANSITION = 4,
    CORNELA_EVENT_GID_TRANSITION = 5,
    CORNELA_EVENT_NAMESPACE_CHANGE = 6,
    CORNELA_EVENT_MOUNT_ATTEMPT = 7,
    CORNELA_EVENT_BPF_ATTEMPT = 8,
    CORNELA_EVENT_CAPABILITY_CHANGE = 9,
    CORNELA_EVENT_MODULE_LOAD = 10,
    CORNELA_EVENT_KEYRING_ACCESS = 11,
};

struct cornela_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 syscall_arg0;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Tracks tgids that have opened an AF_ALG socket. Used to gate high-frequency
// probes (currently splice) so the ringbuf only carries events for processes
// that are part of a Copy-Fail-shaped sequence. Cleared on process exit.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} af_alg_tgids SEC(".maps");

static __always_inline void submit_event(__u32 event_type, __u32 syscall_arg0)
{
    struct cornela_event *event;
    __u64 pid_tgid;
    __u64 uid_gid;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        return;
    }

    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();

    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = event_type;
    event->pid = pid_tgid >> 32;
    event->uid = uid_gid & 0xffffffff;
    event->gid = uid_gid >> 32;
    event->syscall_arg0 = syscall_arg0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
}

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

SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    // sched_process_exit fires for every task exit, including individual
    // worker threads. Only clear the AF_ALG marker when the thread group
    // leader exits (tid == tgid) — otherwise a worker thread terminating
    // would drop the marker while the process is still alive and may still
    // call splice from a sibling thread, producing false negatives.
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = (__u32)(pid_tgid & 0xffffffff);
    __u32 tgid = (__u32)(pid_tgid >> 32);
    if (tid != tgid) {
        return 0;
    }
    bpf_map_delete_elem(&af_alg_tgids, &tgid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    submit_event(CORNELA_EVENT_PROCESS_EXEC, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_UID_TRANSITION, ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_setreuid(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_UID_TRANSITION, ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_setresuid(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_UID_TRANSITION, ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_GID_TRANSITION, ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_setregid(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_GID_TRANSITION, ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_setresgid(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_GID_TRANSITION, ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long flags = ctx->args[0];

    if (flags & CORNELA_NAMESPACE_FLAGS) {
        submit_event(CORNELA_EVENT_NAMESPACE_CHANGE, flags);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_setns(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long nstype = ctx->args[1];

    if (nstype == 0 || (nstype & CORNELA_NAMESPACE_FLAGS)) {
        submit_event(CORNELA_EVENT_NAMESPACE_CHANGE, nstype);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MOUNT_ATTEMPT, ctx->args[3]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int trace_move_mount(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MOUNT_ATTEMPT, ctx->args[4]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int trace_open_tree(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MOUNT_ATTEMPT, ctx->args[2]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int trace_fsopen(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MOUNT_ATTEMPT, ctx->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_bpf(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_BPF_ATTEMPT, ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_CAPABILITY_CHANGE, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_init_module(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MODULE_LOAD, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_finit_module(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MODULE_LOAD, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_delete_module(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_MODULE_LOAD, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int trace_keyctl(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_KEYRING_ACCESS, ctx->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_add_key")
int trace_add_key(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_KEYRING_ACCESS, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_request_key")
int trace_request_key(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_KEYRING_ACCESS, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Apache-2.0";
