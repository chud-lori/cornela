// SPDX-License-Identifier: Apache-2.0
//
// Cornela runtime monitor eBPF program.
//
// This source defines the first probe targets and event payload shape. The
// Rust userspace loader is intentionally not wired yet; keep field sizes stable
// when adding the loader so old JSON/event handling remains compatible.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define AF_ALG 38

enum cornela_event_type {
    CORNELA_EVENT_AF_ALG_SOCKET = 1,
    CORNELA_EVENT_SPLICE = 2,
    CORNELA_EVENT_PROCESS_EXEC = 3,
    CORNELA_EVENT_UID_TRANSITION = 4,
};

struct cornela_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __s32 syscall_arg0;
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline void submit_event(__u32 event_type, __s32 syscall_arg0)
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
        submit_event(CORNELA_EVENT_AF_ALG_SOCKET, family);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int trace_splice(struct trace_event_raw_sys_enter *ctx)
{
    submit_event(CORNELA_EVENT_SPLICE, 0);
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

char LICENSE[] SEC("license") = "Apache-2.0";
