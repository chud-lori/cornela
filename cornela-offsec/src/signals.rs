// Detection-validation signal generators. These fire the syscall *patterns*
// a defensive monitor (Cornela, Falco, Tetragon, Tracee) should pick up,
// without performing exploitation. The point is to prove the detection
// pipeline works end-to-end, not to escape the container.
//
// Linux-only by design (the relevant syscalls don't exist or differ on
// other targets). The non-Linux build returns a stub that produces a
// platform-skipped report so test runners on macOS still compile.

use std::process::id;

#[derive(Debug, Clone)]
pub struct SignalReport {
    pub pattern: String,
    pub iterations: u32,
    pub events_fired: u32,
    pub pid: u32,
    pub notes: Vec<String>,
}

pub fn run(pattern: &str, count: u32) -> Result<SignalReport, String> {
    match pattern {
        "af-alg-splice" => Ok(fire_af_alg_splice(count)),
        other => Err(format!(
            "unknown signal pattern '{other}' — supported: af-alg-splice"
        )),
    }
}

#[cfg(target_os = "linux")]
fn fire_af_alg_splice(count: u32) -> SignalReport {
    use std::os::raw::{c_int, c_uint, c_ulong, c_void};

    // libc bindings, no libc-crate dep. These are the stable Linux syscalls.
    extern "C" {
        fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
        fn pipe2(pipefd: *mut c_int, flags: c_int) -> c_int;
        fn splice(
            fd_in: c_int,
            off_in: *mut i64,
            fd_out: c_int,
            off_out: *mut i64,
            len: c_ulong,
            flags: c_uint,
        ) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    const AF_ALG: c_int = 38;
    const SOCK_SEQPACKET: c_int = 5;
    const O_CLOEXEC: c_int = 0o2000000;

    let mut events = 0u32;
    let mut notes = Vec::new();

    for _ in 0..count {
        // Step 1: socket(AF_ALG, ...) — fires a sys_enter_socket tracepoint
        // event with family=AF_ALG. This is the marker a defender uses to
        // gate the splice probe (per Cornela's monitor.bpf.c). The bind/
        // accept dance is intentionally skipped; we want the syscall to
        // hit the kernel boundary, not to set up a working AF_ALG fd.
        let alg_fd = unsafe { socket(AF_ALG, SOCK_SEQPACKET, 0) };
        if alg_fd < 0 {
            notes.push(
                "socket(AF_ALG) returned -1 — likely seccomp denial or kernel without AF_ALG"
                    .to_string(),
            );
            continue;
        }
        events += 1;

        // Step 2: pipe2() to get a pair of fds we can splice between.
        // splice() requires at least one end to be a pipe.
        let mut fds: [c_int; 2] = [-1, -1];
        let rc = unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) };
        if rc < 0 {
            unsafe {
                close(alg_fd);
            }
            notes.push("pipe2() failed; skipping splice for this iteration".to_string());
            continue;
        }

        // Step 3: splice() with len=0 — generates the sys_enter_splice
        // tracepoint event without actually moving data. The kernel returns
        // 0 immediately for zero-length splice; we don't care about the
        // return value, only that the syscall fires.
        let _ = unsafe {
            splice(
                fds[0],
                std::ptr::null_mut(),
                fds[1],
                std::ptr::null_mut(),
                0,
                0,
            )
        };
        events += 1;

        unsafe {
            close(fds[0]);
            close(fds[1]);
            close(alg_fd);
        }
    }

    if notes.is_empty() {
        notes.push(format!(
            "fired {} syscalls ({} iterations × 2 syscalls per iteration: socket+splice)",
            events, count
        ));
    }

    SignalReport {
        pattern: "af-alg-splice".to_string(),
        iterations: count,
        events_fired: events,
        pid: id(),
        notes,
    }
}

#[cfg(not(target_os = "linux"))]
fn fire_af_alg_splice(count: u32) -> SignalReport {
    SignalReport {
        pattern: "af-alg-splice".to_string(),
        iterations: count,
        events_fired: 0,
        pid: id(),
        notes: vec!["platform skipped: AF_ALG and splice are Linux-only syscalls".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_pattern_errors() {
        assert!(run("unknown-pattern", 1).is_err());
    }

    #[test]
    fn af_alg_splice_returns_report() {
        // On Linux we expect events_fired > 0 (assuming no seccomp blocking
        // socket(AF_ALG) for the test process), on other platforms 0. Test
        // only asserts shape so it works on every dev box.
        let report = run("af-alg-splice", 1).expect("known pattern");
        assert_eq!(report.pattern, "af-alg-splice");
        assert_eq!(report.iterations, 1);
        assert!(!report.notes.is_empty());
    }
}
