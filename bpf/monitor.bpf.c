// Placeholder for the runtime eBPF monitor.
//
// Planned probes:
// - sys_enter_socket
// - sys_enter_splice
// - sched_process_exec
// - UID/GID transition signals where practical
//
// The first MVP intentionally ships the static auditor before loading kernel
// programs, so users can run Cornela without BPF toolchain setup.
