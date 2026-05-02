# Changelog

## 0.1.6-alpha

- Initial experimental Linux container kernel auditor.
- Host hardening audit for kernel, module, seccomp, LSM, namespace, and runtime signals.
- Container discovery from `/proc` cgroups with namespace, capability, seccomp, `NoNewPrivs`, mount, and Docker inspect hints.
- eBPF runtime monitor for AF_ALG, splice, process exec, UID, and GID transition tracepoints.
- eBPF runtime monitor for namespace, mount, BPF, capability, module, and keyring signals.
- Sequence detection for `AF_ALG + splice`, `AF_ALG + splice + UID transition to root`, and namespace-change plus mount-attempt chains.
- Default monitor filtering suppresses Cornela self-events and routine container runtime setup noise.
- CVE-2026-31431 Copy Fail exposure profile.
- JSON, JSONL, and report outputs.
