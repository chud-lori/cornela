use crate::risk::RiskLevel;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum EventType {
    AfAlgSocket,
    Splice,
    ProcessExec,
    PrivilegeTransition,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AfAlgSocket => "af_alg_socket",
            Self::Splice => "splice",
            Self::ProcessExec => "process_exec",
            Self::PrivilegeTransition => "privilege_transition",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvent {
    pub event_type: EventType,
    pub severity: RiskLevel,
    pub pid: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub comm: String,
    pub container_id: Option<String>,
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
            uid: None,
            gid: None,
            comm,
            container_id: None,
            syscall: Some(syscall),
            detail,
            timestamp_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_event_types() {
        assert_eq!(EventType::AfAlgSocket.as_str(), "af_alg_socket");
        assert_eq!(EventType::Splice.as_str(), "splice");
        assert_eq!(EventType::ProcessExec.as_str(), "process_exec");
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
}
