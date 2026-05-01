use std::env;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorStatus {
    pub operating_system: String,
    pub linux_supported: bool,
    pub loader_ready: bool,
    pub sequence_tracking_ready: bool,
    pub event_enrichment_ready: bool,
    pub sequence_window_seconds: u64,
    pub duration_seconds: Option<u64>,
    pub planned_probes: Vec<String>,
    pub reasons: Vec<String>,
}

pub fn preflight(duration_seconds: Option<u64>) -> MonitorStatus {
    let operating_system = env::consts::OS.to_string();
    let linux_supported = operating_system == "linux";
    let planned_probes = planned_probes();
    let mut reasons = Vec::new();

    if !linux_supported {
        reasons.push(format!(
            "runtime eBPF monitoring requires Linux; current OS is {operating_system}"
        ));
    }

    if linux_supported && !Path::new("/sys/kernel/btf/vmlinux").exists() {
        reasons.push("kernel BTF file /sys/kernel/btf/vmlinux was not detected".to_string());
    }

    reasons.push("eBPF userspace loader is not wired yet".to_string());

    MonitorStatus {
        operating_system,
        linux_supported,
        loader_ready: false,
        sequence_tracking_ready: true,
        event_enrichment_ready: true,
        sequence_window_seconds: 30,
        duration_seconds,
        planned_probes,
        reasons,
    }
}

pub fn planned_probes() -> Vec<String> {
    [
        "tracepoint/syscalls/sys_enter_socket",
        "tracepoint/syscalls/sys_enter_splice",
        "tracepoint/sched/sched_process_exec",
    ]
    .iter()
    .map(|probe| (*probe).to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn includes_expected_probe_plan() {
        let probes = planned_probes();

        assert!(probes
            .iter()
            .any(|probe| probe.ends_with("sys_enter_socket")));
        assert!(probes
            .iter()
            .any(|probe| probe.ends_with("sys_enter_splice")));
        assert!(probes
            .iter()
            .any(|probe| probe.ends_with("sched_process_exec")));
    }

    #[test]
    fn carries_requested_duration() {
        let status = preflight(Some(15));

        assert_eq!(status.duration_seconds, Some(15));
        assert!(!status.loader_ready);
        assert!(status.sequence_tracking_ready);
        assert!(status.event_enrichment_ready);
    }
}
