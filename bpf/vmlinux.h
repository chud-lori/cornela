// SPDX-License-Identifier: Apache-2.0
//
// Minimal BTF-style type header for Cornela's initial tracepoint program.
// A generated vmlinux.h is better for broad kernel support, but these
// definitions keep the first monitor build self-contained.

#ifndef CORNELA_MINIMAL_VMLINUX_H
#define CORNELA_MINIMAL_VMLINUX_H

typedef unsigned char __u8;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sched_process_exec {
    __u64 unused;
    char filename[0];
};

#endif
