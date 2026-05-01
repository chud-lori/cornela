use std::env;
use std::path::Path;

#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::container;
#[cfg(target_os = "linux")]
use crate::event::SequenceTracker;
use crate::event::{EventType, RuntimeEvent, SequenceFinding};
use crate::risk::RiskLevel;

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

#[derive(Debug, Clone)]
pub struct MonitorRun {
    pub status: MonitorStatus,
    pub events_seen: u64,
    pub findings: Vec<SequenceFinding>,
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
        reasons.push(
            "kernel BTF file /sys/kernel/btf/vmlinux was not detected; CO-RE portability may be limited"
                .to_string(),
        );
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

pub fn run(duration_seconds: Option<u64>) -> Result<MonitorRun, String> {
    let status = preflight(duration_seconds);

    if !status.linux_supported {
        return Ok(MonitorRun {
            status,
            events_seen: 0,
            findings: Vec::new(),
        });
    }

    run_loader(duration_seconds)
}

#[cfg(target_os = "linux")]
fn run_loader(duration_seconds: Option<u64>) -> Result<MonitorRun, String> {
    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::{include_bytes_aligned, Ebpf};
    use std::convert::TryInto;

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/monitor.bpf.o"
    )))
    .map_err(|err| format!("failed to load eBPF object: {err}"))?;

    attach_tracepoint(&mut bpf, "trace_socket", "syscalls", "sys_enter_socket")?;
    attach_tracepoint(&mut bpf, "trace_splice", "syscalls", "sys_enter_splice")?;
    attach_tracepoint(&mut bpf, "trace_exec", "sched", "sched_process_exec")?;

    let mut ring = RingBuf::try_from(
        bpf.map_mut("events")
            .ok_or_else(|| "events ring buffer map not found".to_string())?,
    )
    .map_err(|err| format!("failed to open events ring buffer: {err}"))?;

    let deadline = duration_seconds.map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let mut tracker = SequenceTracker::copy_fail_default();
    let mut findings = Vec::new();
    let mut events_seen = 0_u64;

    loop {
        while let Some(item) = ring.next() {
            if let Some(raw) = parse_raw_event(&item) {
                let mut event = raw.into_runtime_event();
                container::enrich_event(&mut event);
                findings.extend(tracker.observe(&event));
                events_seen += 1;
            }
        }

        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let mut status = preflight(duration_seconds);
    status.loader_ready = true;
    status
        .reasons
        .retain(|reason| reason != "eBPF userspace loader is not wired yet");

    Ok(MonitorRun {
        status,
        events_seen,
        findings,
    })
}

#[cfg(not(target_os = "linux"))]
fn run_loader(_duration_seconds: Option<u64>) -> Result<MonitorRun, String> {
    unreachable!("run_loader is only called after linux_supported is true")
}

#[cfg(target_os = "linux")]
fn attach_tracepoint(
    bpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<(), String> {
    let program: &mut aya::programs::TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("{program_name} program not found"))?
        .try_into()
        .map_err(|err| format!("failed to access {program_name}: {err}"))?;
    program
        .load()
        .map_err(|err| format!("failed to load {program_name}: {err}"))?;
    program
        .attach(category, name)
        .map_err(|err| format!("failed to attach {program_name}: {err}"))?;
    Ok(())
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
struct RawBpfEvent {
    timestamp_ns: u64,
    event_type: u32,
    pid: u32,
    uid: u32,
    gid: u32,
    syscall_arg0: i32,
    comm: [u8; 16],
}

impl RawBpfEvent {
    #[allow(dead_code)]
    fn into_runtime_event(self) -> RuntimeEvent {
        let event_type = match self.event_type {
            1 => EventType::AfAlgSocket,
            2 => EventType::Splice,
            3 => EventType::ProcessExec,
            _ => EventType::ProcessExec,
        };
        let syscall = match event_type {
            EventType::AfAlgSocket => Some("socket".to_string()),
            EventType::Splice => Some("splice".to_string()),
            EventType::ProcessExec => Some("exec".to_string()),
            EventType::PrivilegeTransition => None,
        };
        let detail = match event_type {
            EventType::AfAlgSocket => format!("family={}", self.syscall_arg0),
            EventType::Splice => "splice called".to_string(),
            EventType::ProcessExec => "process exec".to_string(),
            EventType::PrivilegeTransition => "privilege transition".to_string(),
        };

        RuntimeEvent {
            event_type,
            severity: RiskLevel::Medium,
            pid: self.pid,
            ppid: None,
            uid: Some(self.uid),
            gid: Some(self.gid),
            comm: comm_to_string(&self.comm),
            command_line: None,
            container_id: None,
            cgroup_path: None,
            pid_namespace: None,
            mount_namespace: None,
            network_namespace: None,
            syscall,
            detail,
            timestamp_ns: self.timestamp_ns,
        }
    }
}

#[allow(dead_code)]
fn parse_raw_event(bytes: &[u8]) -> Option<RawBpfEvent> {
    if bytes.len() < std::mem::size_of::<RawBpfEvent>() {
        return None;
    }

    let ptr = bytes.as_ptr().cast::<RawBpfEvent>();
    Some(unsafe { std::ptr::read_unaligned(ptr) })
}

#[allow(dead_code)]
fn comm_to_string(comm: &[u8; 16]) -> String {
    let end = comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).to_string()
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

    #[test]
    fn converts_raw_event_to_runtime_event() {
        let mut comm = [0_u8; 16];
        comm[..6].copy_from_slice(b"python");
        let raw = RawBpfEvent {
            timestamp_ns: 123,
            event_type: 1,
            pid: 42,
            uid: 1000,
            gid: 1000,
            syscall_arg0: 38,
            comm,
        };

        let event = raw.into_runtime_event();

        assert_eq!(event.event_type, EventType::AfAlgSocket);
        assert_eq!(event.comm, "python");
        assert_eq!(event.syscall.as_deref(), Some("socket"));
    }
}
