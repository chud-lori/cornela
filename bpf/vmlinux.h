// SPDX-License-Identifier: Apache-2.0
//
// Minimal BTF-style type header for Cornela's initial tracepoint program.
// A generated vmlinux.h is better for broad kernel support, but these
// definitions keep the first monitor build self-contained.

#ifndef CORNELA_MINIMAL_VMLINUX_H
#define CORNELA_MINIMAL_VMLINUX_H

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

enum bpf_map_type {
    BPF_MAP_TYPE_HASH = 1,
    BPF_MAP_TYPE_RINGBUF = 27,
};

#ifndef BPF_ANY
#define BPF_ANY 0
#endif

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sched_process_exec {
    __u64 unused;
    char filename[0];
};

struct trace_event_raw_sched_process_template {
    __u64 unused;
    char comm[16];
    int pid;
    int prio;
};

#endif
