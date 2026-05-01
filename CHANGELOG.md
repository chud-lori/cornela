# Changelog

## 0.1.0-alpha

- Initial experimental Linux container kernel auditor.
- Host hardening audit for kernel, module, seccomp, LSM, namespace, and runtime signals.
- Container discovery from `/proc` cgroups with namespace, capability, seccomp, `NoNewPrivs`, mount, and Docker inspect hints.
- eBPF runtime monitor for AF_ALG, splice, process exec, UID, and GID transition tracepoints.
- Sequence detection for `AF_ALG + splice` and `AF_ALG + splice + UID transition to root`.
- CVE-2026-31431 Copy Fail exposure profile.
- JSON, JSONL, and report outputs.
