use std::env;
use std::path::Path;

#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use crate::container;
use crate::event::{EventType, RuntimeEvent, SequenceFinding, SequenceTracker};
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
    pub max_events: Option<u64>,
    pub planned_probes: Vec<String>,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MonitorOptions {
    pub duration_seconds: Option<u64>,
    pub simulate: bool,
    pub collect_events: bool,
    pub jsonl: bool,
    pub max_events: Option<u64>,
    pub event_filter: EventFilter,
}

#[derive(Debug, Clone)]
pub struct MonitorRun {
    pub status: MonitorStatus,
    pub simulated: bool,
    pub events_seen: u64,
    pub events_emitted: u64,
    pub events: Vec<RuntimeEvent>,
    pub findings: Vec<SequenceFinding>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventFilter {
    Interesting,
    All,
}

pub fn preflight(duration_seconds: Option<u64>, max_events: Option<u64>) -> MonitorStatus {
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

    reasons.push("preflight only; eBPF loader has not attached probes in this mode".to_string());

    MonitorStatus {
        operating_system,
        linux_supported,
        loader_ready: false,
        sequence_tracking_ready: true,
        event_enrichment_ready: true,
        sequence_window_seconds: 30,
        duration_seconds,
        max_events,
        planned_probes,
        reasons,
    }
}

pub fn planned_probes() -> Vec<String> {
    [
        "tracepoint/syscalls/sys_enter_socket",
        "tracepoint/syscalls/sys_enter_splice",
        "tracepoint/sched/sched_process_exec",
        "tracepoint/syscalls/sys_enter_setuid",
        "tracepoint/syscalls/sys_enter_setreuid",
        "tracepoint/syscalls/sys_enter_setresuid",
        "tracepoint/syscalls/sys_enter_setgid",
        "tracepoint/syscalls/sys_enter_setregid",
        "tracepoint/syscalls/sys_enter_setresgid",
        "tracepoint/syscalls/sys_enter_unshare",
        "tracepoint/syscalls/sys_enter_setns",
        "tracepoint/syscalls/sys_enter_mount",
        "tracepoint/syscalls/sys_enter_move_mount",
        "tracepoint/syscalls/sys_enter_open_tree",
        "tracepoint/syscalls/sys_enter_fsopen",
        "tracepoint/syscalls/sys_enter_bpf",
        "tracepoint/syscalls/sys_enter_capset",
        "tracepoint/syscalls/sys_enter_init_module",
        "tracepoint/syscalls/sys_enter_finit_module",
        "tracepoint/syscalls/sys_enter_delete_module",
        "tracepoint/syscalls/sys_enter_keyctl",
        "tracepoint/syscalls/sys_enter_add_key",
        "tracepoint/syscalls/sys_enter_request_key",
    ]
    .iter()
    .map(|probe| (*probe).to_string())
    .collect()
}

pub fn run(options: MonitorOptions) -> Result<MonitorRun, String> {
    if options.simulate {
        return Ok(simulate_run(&options));
    }

    let status = preflight(options.duration_seconds, options.max_events);

    if !status.linux_supported {
        return Ok(MonitorRun {
            status,
            simulated: false,
            events_seen: 0,
            events_emitted: 0,
            events: Vec::new(),
            findings: Vec::new(),
        });
    }

    run_loader(&options)
}

#[cfg(target_os = "linux")]
fn run_loader(options: &MonitorOptions) -> Result<MonitorRun, String> {
    use aya::maps::RingBuf;
    use aya::{include_bytes_aligned, Ebpf};

    let mut bpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/monitor.bpf.o"
    )))
    .map_err(|err| format!("failed to load eBPF object: {err}"))?;

    attach_tracepoint(&mut bpf, "trace_socket", "syscalls", "sys_enter_socket")?;
    attach_tracepoint(&mut bpf, "trace_splice", "syscalls", "sys_enter_splice")?;
    attach_tracepoint(&mut bpf, "trace_exec", "sched", "sched_process_exec")?;
    attach_tracepoint(&mut bpf, "trace_setuid", "syscalls", "sys_enter_setuid")?;
    attach_tracepoint(&mut bpf, "trace_setreuid", "syscalls", "sys_enter_setreuid")?;
    attach_tracepoint(
        &mut bpf,
        "trace_setresuid",
        "syscalls",
        "sys_enter_setresuid",
    )?;
    attach_tracepoint(&mut bpf, "trace_setgid", "syscalls", "sys_enter_setgid")?;
    attach_tracepoint(&mut bpf, "trace_setregid", "syscalls", "sys_enter_setregid")?;
    attach_tracepoint(
        &mut bpf,
        "trace_setresgid",
        "syscalls",
        "sys_enter_setresgid",
    )?;
    let mut skipped_probes = Vec::new();
    attach_optional_tracepoint(
        &mut bpf,
        "trace_unshare",
        "syscalls",
        "sys_enter_unshare",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_setns",
        "syscalls",
        "sys_enter_setns",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_mount",
        "syscalls",
        "sys_enter_mount",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_move_mount",
        "syscalls",
        "sys_enter_move_mount",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_open_tree",
        "syscalls",
        "sys_enter_open_tree",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_fsopen",
        "syscalls",
        "sys_enter_fsopen",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_bpf",
        "syscalls",
        "sys_enter_bpf",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_capset",
        "syscalls",
        "sys_enter_capset",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_init_module",
        "syscalls",
        "sys_enter_init_module",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_finit_module",
        "syscalls",
        "sys_enter_finit_module",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_delete_module",
        "syscalls",
        "sys_enter_delete_module",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_keyctl",
        "syscalls",
        "sys_enter_keyctl",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_add_key",
        "syscalls",
        "sys_enter_add_key",
        &mut skipped_probes,
    );
    attach_optional_tracepoint(
        &mut bpf,
        "trace_request_key",
        "syscalls",
        "sys_enter_request_key",
        &mut skipped_probes,
    );
    let mut ring = RingBuf::try_from(
        bpf.map_mut("events")
            .ok_or_else(|| "events ring buffer map not found".to_string())?,
    )
    .map_err(|err| format!("failed to open events ring buffer: {err}"))?;

    let deadline = options
        .duration_seconds
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let mut tracker = SequenceTracker::copy_fail_default();
    let mut findings = Vec::new();
    let mut events = Vec::new();
    let mut events_seen = 0_u64;
    let mut events_emitted = 0_u64;

    loop {
        while let Some(item) = ring.next() {
            if let Some(raw) = parse_raw_event(&item) {
                let mut event = raw.into_runtime_event();
                container::enrich_event(&mut event);
                events_seen += 1;
                if should_suppress_event(&event, options.event_filter) {
                    continue;
                }

                let emit_event = should_emit_event(&event, options.event_filter);
                if options.jsonl && emit_event {
                    println!("{}", crate::json::runtime_event_to_jsonl(&event));
                }
                let new_findings = tracker.observe(&event);
                if options.jsonl {
                    for finding in &new_findings {
                        println!("{}", crate::json::sequence_finding_to_jsonl(finding));
                    }
                }
                findings.extend(new_findings);
                if emit_event {
                    events_emitted += 1;
                }
                if options.collect_events && emit_event {
                    events.push(event);
                }

                if reached_max_events(events_seen, options.max_events) || deadline_reached(deadline)
                {
                    break;
                }
            }
        }

        if reached_max_events(events_seen, options.max_events) || deadline_reached(deadline) {
            break;
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let mut status = preflight(options.duration_seconds, options.max_events);
    status.loader_ready = true;
    status.reasons.retain(|reason| {
        reason != "preflight only; eBPF loader has not attached probes in this mode"
    });
    for probe in skipped_probes {
        status
            .reasons
            .push(format!("optional probe was not attached: {probe}"));
    }

    Ok(MonitorRun {
        status,
        simulated: false,
        events_seen,
        events_emitted,
        events,
        findings,
    })
}

#[cfg(not(target_os = "linux"))]
fn run_loader(_options: &MonitorOptions) -> Result<MonitorRun, String> {
    unreachable!("run_loader is only called after linux_supported is true")
}

fn simulate_run(options: &MonitorOptions) -> MonitorRun {
    let mut status = preflight(options.duration_seconds, options.max_events);
    status.loader_ready = false;
    status.reasons.clear();
    status
        .reasons
        .push("simulation mode generated synthetic AF_ALG and splice events".to_string());

    let mut tracker = SequenceTracker::copy_fail_default();
    let events = simulated_events();
    let mut findings = Vec::new();
    let mut events_seen = 0_u64;
    let mut events_emitted = 0_u64;
    let mut collected_events = Vec::new();

    for event in &events {
        events_seen += 1;
        if should_suppress_event(event, options.event_filter) {
            continue;
        }
        let emit_event = should_emit_event(event, options.event_filter);
        if options.jsonl && emit_event {
            println!("{}", crate::json::runtime_event_to_jsonl(event));
        }
        let new_findings = tracker.observe(event);
        if options.jsonl {
            for finding in &new_findings {
                println!("{}", crate::json::sequence_finding_to_jsonl(finding));
            }
        }
        findings.extend(new_findings);
        if emit_event {
            events_emitted += 1;
        }
        if options.collect_events && emit_event {
            collected_events.push(event.clone());
        }
        if reached_max_events(events_seen, options.max_events) {
            break;
        }
    }

    MonitorRun {
        status,
        simulated: true,
        events_seen,
        events_emitted,
        events: collected_events,
        findings,
    }
}

fn should_emit_event(event: &RuntimeEvent, filter: EventFilter) -> bool {
    match filter {
        EventFilter::All => true,
        EventFilter::Interesting => match event.event_type {
            EventType::AfAlgSocket
            | EventType::Splice
            | EventType::NamespaceChange
            | EventType::MountAttempt
            | EventType::BpfAttempt
            | EventType::CapabilityChange
            | EventType::ModuleLoad
            | EventType::KeyringAccess => true,
            EventType::PrivilegeTransition => event.detail.contains("target_uid=0"),
            EventType::GroupTransition => event.detail.contains("target_gid=0"),
            EventType::ProcessExec => {
                let text = event
                    .command_line
                    .as_deref()
                    .unwrap_or(event.detail.as_str());
                ["/usr/bin/su", "/bin/su", "sudo", "/usr/bin/sudo"]
                    .iter()
                    .any(|target| text.contains(target))
            }
        },
    }
}

fn should_suppress_event(event: &RuntimeEvent, filter: EventFilter) -> bool {
    if matches!(filter, EventFilter::All) {
        return false;
    }

    if event.comm == "cornela" {
        return true;
    }

    match event.event_type {
        EventType::NamespaceChange
        | EventType::MountAttempt
        | EventType::CapabilityChange
        | EventType::KeyringAccess
        | EventType::PrivilegeTransition
        | EventType::GroupTransition => is_runtime_setup_noise(event),
        _ => false,
    }
}

fn is_runtime_setup_noise(event: &RuntimeEvent) -> bool {
    event.comm.starts_with("runc")
        || event.comm.starts_with("containerd")
        || event.comm == "dockerd"
        || event.command_line.as_deref().is_some_and(|command| {
            command.contains("/runc")
                || command.contains("containerd-shim")
                || command.contains("docker-init")
        })
}

fn reached_max_events(events_seen: u64, max_events: Option<u64>) -> bool {
    max_events.is_some_and(|max_events| events_seen >= max_events)
}

#[cfg(target_os = "linux")]
fn deadline_reached(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

fn simulated_events() -> Vec<RuntimeEvent> {
    let mut first = RuntimeEvent::suspicious_syscall(
        EventType::AfAlgSocket,
        4242,
        "python3".to_string(),
        "socket".to_string(),
        "family=AF_ALG".to_string(),
        1_000,
    );
    first.container_id = Some("simulated-container".to_string());
    first.cgroup_path = Some("/docker/simulated-container".to_string());

    let mut second = RuntimeEvent::suspicious_syscall(
        EventType::Splice,
        4242,
        "python3".to_string(),
        "splice".to_string(),
        "splice called".to_string(),
        2_000,
    );
    second.container_id = Some("simulated-container".to_string());
    second.cgroup_path = Some("/docker/simulated-container".to_string());

    let mut third = RuntimeEvent::suspicious_syscall(
        EventType::PrivilegeTransition,
        4242,
        "python3".to_string(),
        "setuid".to_string(),
        "target_uid=0".to_string(),
        3_000,
    );
    third.container_id = Some("simulated-container".to_string());
    third.cgroup_path = Some("/docker/simulated-container".to_string());

    let mut fourth = RuntimeEvent::suspicious_syscall(
        EventType::BpfAttempt,
        4242,
        "python3".to_string(),
        "bpf".to_string(),
        "bpf command=5".to_string(),
        4_000,
    );
    fourth.container_id = Some("simulated-container".to_string());
    fourth.cgroup_path = Some("/docker/simulated-container".to_string());

    vec![first, second, third, fourth]
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

#[cfg(target_os = "linux")]
fn attach_optional_tracepoint(
    bpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
    skipped: &mut Vec<String>,
) {
    if let Err(err) = attach_tracepoint(bpf, program_name, category, name) {
        skipped.push(format!("{category}/{name} ({err})"));
    }
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
            4 => EventType::PrivilegeTransition,
            5 => EventType::GroupTransition,
            6 => EventType::NamespaceChange,
            7 => EventType::MountAttempt,
            8 => EventType::BpfAttempt,
            9 => EventType::CapabilityChange,
            10 => EventType::ModuleLoad,
            11 => EventType::KeyringAccess,
            _ => EventType::ProcessExec,
        };
        let syscall = match event_type {
            EventType::AfAlgSocket => Some("socket".to_string()),
            EventType::Splice => Some("splice".to_string()),
            EventType::ProcessExec => Some("exec".to_string()),
            EventType::PrivilegeTransition => Some("setuid".to_string()),
            EventType::GroupTransition => Some("setgid".to_string()),
            EventType::NamespaceChange => Some("namespace".to_string()),
            EventType::MountAttempt => Some("mount".to_string()),
            EventType::BpfAttempt => Some("bpf".to_string()),
            EventType::CapabilityChange => Some("capset".to_string()),
            EventType::ModuleLoad => Some("module".to_string()),
            EventType::KeyringAccess => Some("keyring".to_string()),
        };
        let detail = match event_type {
            EventType::AfAlgSocket => format!("family={}", self.syscall_arg0),
            EventType::Splice => "splice called".to_string(),
            EventType::ProcessExec => "process exec".to_string(),
            EventType::PrivilegeTransition => format!("target_uid={}", self.syscall_arg0),
            EventType::GroupTransition => format!("target_gid={}", self.syscall_arg0),
            EventType::NamespaceChange => format!("namespace flags={}", self.syscall_arg0),
            EventType::MountAttempt => format!("mount flags={}", self.syscall_arg0),
            EventType::BpfAttempt => format!("bpf command={}", self.syscall_arg0),
            EventType::CapabilityChange => "capset called".to_string(),
            EventType::ModuleLoad => "kernel module syscall called".to_string(),
            EventType::KeyringAccess => format!("keyring operation={}", self.syscall_arg0),
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
fn comm_to_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
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
        let status = preflight(Some(15), Some(99));

        assert_eq!(status.duration_seconds, Some(15));
        assert_eq!(status.max_events, Some(99));
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

    #[test]
    fn simulation_produces_sequence_finding() {
        let run = simulate_run(&MonitorOptions {
            duration_seconds: Some(1),
            simulate: true,
            collect_events: true,
            jsonl: false,
            max_events: None,
            event_filter: EventFilter::Interesting,
        });

        assert!(run.simulated);
        assert_eq!(run.events_seen, 4);
        assert_eq!(run.events_emitted, 4);
        assert_eq!(run.events.len(), 4);
        assert!(run
            .findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::High));
        assert!(run
            .findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::Critical));
    }

    #[test]
    fn simulation_honors_max_events() {
        let run = simulate_run(&MonitorOptions {
            duration_seconds: None,
            simulate: true,
            collect_events: true,
            jsonl: false,
            max_events: Some(2),
            event_filter: EventFilter::Interesting,
        });

        assert_eq!(run.events_seen, 2);
        assert_eq!(run.events_emitted, 2);
        assert_eq!(run.events.len(), 2);
        assert!(run
            .findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::High));
        assert!(!run
            .findings
            .iter()
            .any(|finding| finding.severity == RiskLevel::Critical));
    }

    #[test]
    fn interesting_filter_suppresses_routine_exec_and_non_root_uid_changes() {
        let exec = RuntimeEvent::suspicious_syscall(
            EventType::ProcessExec,
            1,
            "uname".to_string(),
            "exec".to_string(),
            "process exec".to_string(),
            1,
        );
        let non_root_uid = RuntimeEvent::suspicious_syscall(
            EventType::PrivilegeTransition,
            2,
            "sshd".to_string(),
            "setuid".to_string(),
            "target_uid=-1".to_string(),
            2,
        );
        let root_uid = RuntimeEvent::suspicious_syscall(
            EventType::PrivilegeTransition,
            3,
            "worker".to_string(),
            "setuid".to_string(),
            "target_uid=0".to_string(),
            3,
        );

        assert!(!should_emit_event(&exec, EventFilter::Interesting));
        assert!(!should_emit_event(&non_root_uid, EventFilter::Interesting));
        assert!(should_emit_event(&root_uid, EventFilter::Interesting));
        assert!(should_emit_event(&exec, EventFilter::All));
    }

    #[test]
    fn default_filter_suppresses_cornela_self_events() {
        let event = RuntimeEvent::suspicious_syscall(
            EventType::BpfAttempt,
            1,
            "cornela".to_string(),
            "bpf".to_string(),
            "bpf command=5".to_string(),
            1,
        );

        assert!(should_suppress_event(&event, EventFilter::Interesting));
        assert!(!should_suppress_event(&event, EventFilter::All));
    }

    #[test]
    fn default_filter_suppresses_runtime_setup_noise() {
        let event = RuntimeEvent::suspicious_syscall(
            EventType::MountAttempt,
            1,
            "runc".to_string(),
            "mount".to_string(),
            "mount flags=1".to_string(),
            1,
        );

        assert!(should_suppress_event(&event, EventFilter::Interesting));
        assert!(!should_suppress_event(&event, EventFilter::All));
    }
}
