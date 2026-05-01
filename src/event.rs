use crate::risk::RiskLevel;

#[allow(dead_code)]
const DEFAULT_SEQUENCE_WINDOW_NS: u64 = 30_000_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EventType {
    AfAlgSocket,
    Splice,
    ProcessExec,
    PrivilegeTransition,
    GroupTransition,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AfAlgSocket => "af_alg_socket",
            Self::Splice => "splice",
            Self::ProcessExec => "process_exec",
            Self::PrivilegeTransition => "privilege_transition",
            Self::GroupTransition => "group_transition",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event_type: EventType,
    pub severity: RiskLevel,
    pub pid: u32,
    pub ppid: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub comm: String,
    pub command_line: Option<String>,
    pub container_id: Option<String>,
    pub cgroup_path: Option<String>,
    pub pid_namespace: Option<String>,
    pub mount_namespace: Option<String>,
    pub network_namespace: Option<String>,
    pub syscall: Option<String>,
    pub detail: String,
    pub timestamp_ns: u64,
}

impl RuntimeEvent {
    #[allow(dead_code)]
    pub fn suspicious_syscall(
        event_type: EventType,
        pid: u32,
        comm: String,
        syscall: String,
        detail: String,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            event_type,
            severity: RiskLevel::High,
            pid,
            ppid: None,
            uid: None,
            gid: None,
            comm,
            command_line: None,
            container_id: None,
            cgroup_path: None,
            pid_namespace: None,
            mount_namespace: None,
            network_namespace: None,
            syscall: Some(syscall),
            detail,
            timestamp_ns,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceFinding {
    pub severity: RiskLevel,
    pub pid: u32,
    pub container_id: Option<String>,
    pub first_timestamp_ns: u64,
    pub last_timestamp_ns: u64,
    pub event_types: Vec<EventType>,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct SequenceTracker {
    window_ns: u64,
    states: Vec<SequenceState>,
}

#[derive(Debug, Clone)]
struct SequenceState {
    pid: u32,
    container_id: Option<String>,
    saw_af_alg: Option<u64>,
    saw_splice: Option<u64>,
    saw_setuid_exec: Option<u64>,
    saw_uid_transition_to_root: Option<u64>,
    reported_copy_fail_pair: bool,
    reported_copy_fail_critical: bool,
}

impl SequenceTracker {
    #[allow(dead_code)]
    pub fn new(window_ns: u64) -> Self {
        Self {
            window_ns,
            states: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn copy_fail_default() -> Self {
        Self::new(DEFAULT_SEQUENCE_WINDOW_NS)
    }

    #[allow(dead_code)]
    pub fn observe(&mut self, event: &RuntimeEvent) -> Vec<SequenceFinding> {
        self.expire_old_states(event.timestamp_ns);

        let index = self.state_index(event);
        apply_event(&mut self.states[index], event);

        let mut findings = Vec::new();
        if let Some(finding) = copy_fail_pair_finding(&mut self.states[index], self.window_ns) {
            findings.push(finding);
        }
        if let Some(finding) = copy_fail_critical_finding(&mut self.states[index], self.window_ns) {
            findings.push(finding);
        }

        findings
    }

    #[allow(dead_code)]
    fn state_index(&mut self, event: &RuntimeEvent) -> usize {
        if let Some(index) = self
            .states
            .iter()
            .position(|state| state.pid == event.pid && state.container_id == event.container_id)
        {
            return index;
        }

        self.states.push(SequenceState {
            pid: event.pid,
            container_id: event.container_id.clone(),
            saw_af_alg: None,
            saw_splice: None,
            saw_setuid_exec: None,
            saw_uid_transition_to_root: None,
            reported_copy_fail_pair: false,
            reported_copy_fail_critical: false,
        });
        self.states.len() - 1
    }

    #[allow(dead_code)]
    fn expire_old_states(&mut self, now_ns: u64) {
        let window_ns = self.window_ns;
        self.states.retain(|state| {
            let latest = [
                state.saw_af_alg,
                state.saw_splice,
                state.saw_setuid_exec,
                state.saw_uid_transition_to_root,
            ]
            .into_iter()
            .flatten()
            .max()
            .unwrap_or(0);
            now_ns.saturating_sub(latest) <= window_ns
        });
    }
}

impl Default for SequenceTracker {
    fn default() -> Self {
        Self::copy_fail_default()
    }
}

#[allow(dead_code)]
fn apply_event(state: &mut SequenceState, event: &RuntimeEvent) {
    match event.event_type {
        EventType::AfAlgSocket => state.saw_af_alg = Some(event.timestamp_ns),
        EventType::Splice => state.saw_splice = Some(event.timestamp_ns),
        EventType::ProcessExec if looks_like_setuid_target(event) => {
            state.saw_setuid_exec = Some(event.timestamp_ns)
        }
        EventType::PrivilegeTransition if targets_root(event) => {
            state.saw_uid_transition_to_root = Some(event.timestamp_ns)
        }
        EventType::GroupTransition => {}
        _ => {}
    }
}

#[allow(dead_code)]
fn copy_fail_pair_finding(state: &mut SequenceState, window_ns: u64) -> Option<SequenceFinding> {
    if state.reported_copy_fail_pair {
        return None;
    }

    let af_alg = state.saw_af_alg?;
    let splice = state.saw_splice?;
    let first = af_alg.min(splice);
    let last = af_alg.max(splice);

    if last.saturating_sub(first) > window_ns {
        return None;
    }

    state.reported_copy_fail_pair = true;

    Some(SequenceFinding {
        severity: RiskLevel::High,
        pid: state.pid,
        container_id: state.container_id.clone(),
        first_timestamp_ns: first,
        last_timestamp_ns: last,
        event_types: vec![EventType::AfAlgSocket, EventType::Splice],
        reason: "process used AF_ALG and splice within the Copy Fail correlation window"
            .to_string(),
    })
}

#[allow(dead_code)]
fn copy_fail_critical_finding(
    state: &mut SequenceState,
    window_ns: u64,
) -> Option<SequenceFinding> {
    if state.reported_copy_fail_critical {
        return None;
    }

    let af_alg = state.saw_af_alg?;
    let splice = state.saw_splice?;
    let uid_transition = state.saw_uid_transition_to_root?;
    let first = af_alg.min(splice).min(uid_transition);
    let last = af_alg.max(splice).max(uid_transition);

    if last.saturating_sub(first) > window_ns {
        return None;
    }

    state.reported_copy_fail_critical = true;

    Some(SequenceFinding {
        severity: RiskLevel::Critical,
        pid: state.pid,
        container_id: state.container_id.clone(),
        first_timestamp_ns: first,
        last_timestamp_ns: last,
        event_types: vec![
            EventType::AfAlgSocket,
            EventType::Splice,
            EventType::PrivilegeTransition,
        ],
        reason: "process used AF_ALG and splice before a UID transition to root within the Copy Fail correlation window"
            .to_string(),
    })
}

#[allow(dead_code)]
fn looks_like_setuid_target(event: &RuntimeEvent) -> bool {
    let text = event
        .command_line
        .as_deref()
        .unwrap_or(event.detail.as_str());

    ["/usr/bin/su", "/bin/su", "sudo", "/usr/bin/sudo"]
        .iter()
        .any(|target| text.contains(target))
}

fn targets_root(event: &RuntimeEvent) -> bool {
    event.detail.contains("target_uid=0") || matches!(event.uid, Some(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_event_types() {
        assert_eq!(EventType::AfAlgSocket.as_str(), "af_alg_socket");
        assert_eq!(EventType::Splice.as_str(), "splice");
        assert_eq!(EventType::ProcessExec.as_str(), "process_exec");
        assert_eq!(EventType::GroupTransition.as_str(), "group_transition");
    }

    #[test]
    fn builds_suspicious_syscall_event() {
        let event = RuntimeEvent::suspicious_syscall(
            EventType::AfAlgSocket,
            42,
            "python3".to_string(),
            "socket".to_string(),
            "family=AF_ALG".to_string(),
            123,
        );

        assert_eq!(event.severity, RiskLevel::High);
        assert_eq!(event.pid, 42);
        assert_eq!(event.syscall.as_deref(), Some("socket"));
    }

    #[test]
    fn correlates_af_alg_and_splice_for_same_process() {
        let mut tracker = SequenceTracker::new(30);
        let first = RuntimeEvent::suspicious_syscall(
            EventType::AfAlgSocket,
            42,
            "python3".to_string(),
            "socket".to_string(),
            "family=AF_ALG".to_string(),
            100,
        );
        let second = RuntimeEvent::suspicious_syscall(
            EventType::Splice,
            42,
            "python3".to_string(),
            "splice".to_string(),
            "splice".to_string(),
            120,
        );

        assert!(tracker.observe(&first).is_empty());
        let findings = tracker.observe(&second);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, RiskLevel::High);
    }

    #[test]
    fn does_not_correlate_outside_window() {
        let mut tracker = SequenceTracker::new(10);
        let first = RuntimeEvent::suspicious_syscall(
            EventType::AfAlgSocket,
            42,
            "python3".to_string(),
            "socket".to_string(),
            "family=AF_ALG".to_string(),
            100,
        );
        let second = RuntimeEvent::suspicious_syscall(
            EventType::Splice,
            42,
            "python3".to_string(),
            "splice".to_string(),
            "splice".to_string(),
            120,
        );

        tracker.observe(&first);
        assert!(tracker.observe(&second).is_empty());
    }

    #[test]
    fn escalates_to_critical_after_root_uid_transition() {
        let mut tracker = SequenceTracker::new(50);
        let first = RuntimeEvent::suspicious_syscall(
            EventType::AfAlgSocket,
            42,
            "python3".to_string(),
            "socket".to_string(),
            "family=AF_ALG".to_string(),
            100,
        );
        let second = RuntimeEvent::suspicious_syscall(
            EventType::Splice,
            42,
            "python3".to_string(),
            "splice".to_string(),
            "splice".to_string(),
            120,
        );
        let third = RuntimeEvent::suspicious_syscall(
            EventType::PrivilegeTransition,
            42,
            "python3".to_string(),
            "setuid".to_string(),
            "target_uid=0".to_string(),
            130,
        );

        assert!(tracker.observe(&first).is_empty());
        let high = tracker.observe(&second);
        let critical = tracker.observe(&third);

        assert_eq!(high.len(), 1);
        assert_eq!(high[0].severity, RiskLevel::High);
        assert_eq!(critical.len(), 1);
        assert_eq!(critical[0].severity, RiskLevel::Critical);
    }
}
