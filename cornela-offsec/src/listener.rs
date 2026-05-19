// Reverse-shell catcher. Binds a TCP socket, accepts a connection, and
// bridges stdin <-> socket <-> stdout. Pure std::net + std::thread.
//
// Modes:
//   --once    : exit after the first session disconnects (default)
//   (else)    : after a session ends, accept the next one
//   --timeout : 0 = wait forever, otherwise exit after N seconds idle

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ListenerReport {
    pub bind: String,
    pub port: u16,
    pub kind: String,
    pub once: bool,
    pub sessions: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ListenerOptions<'a> {
    pub kind: &'a str,
    pub bind: &'a str,
    pub port: u16,
    pub once: bool,
    pub timeout_secs: u64,
}

pub fn run(opts: ListenerOptions<'_>) -> Result<ListenerReport, String> {
    if opts.kind != "tcp" {
        return Err(format!(
            "unknown listener kind '{}' — supported: tcp",
            opts.kind
        ));
    }

    let bind_addr = format!("{}:{}", opts.bind, opts.port);
    let listener = TcpListener::bind(&bind_addr).map_err(|err| format!("bind failed: {err}"))?;
    let _ = listener.set_nonblocking(false);

    eprintln!(
        "cornela-offsec: listening on {bind_addr} ({mode}). Ctrl-C to abort.",
        mode = if opts.once { "single session" } else { "loop" },
    );

    let mut report = ListenerReport {
        bind: opts.bind.to_string(),
        port: opts.port,
        kind: opts.kind.to_string(),
        once: opts.once,
        sessions: 0,
        error: None,
    };

    if opts.timeout_secs > 0 {
        let _ = listener.set_nonblocking(true);
        let started = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok((stream, peer)) => {
                    let _ = stream.set_nonblocking(false);
                    eprintln!("cornela-offsec: session opened from {peer}");
                    if let Err(err) = handle_session(stream) {
                        report.error = Some(format!("session error: {err}"));
                    }
                    report.sessions += 1;
                    if opts.once {
                        return Ok(report);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if started.elapsed().as_secs() >= opts.timeout_secs {
                        report.error = Some("timeout reached without a session".to_string());
                        return Ok(report);
                    }
                    thread::sleep(Duration::from_millis(200));
                }
                Err(err) => {
                    report.error = Some(format!("accept failed: {err}"));
                    return Ok(report);
                }
            }
        }
    }

    loop {
        let (stream, peer) = listener
            .accept()
            .map_err(|err| format!("accept failed: {err}"))?;
        eprintln!("cornela-offsec: session opened from {peer}");
        if let Err(err) = handle_session(stream) {
            report.error = Some(format!("session error: {err}"));
        }
        report.sessions += 1;
        if opts.once {
            return Ok(report);
        }
    }
}

fn handle_session(stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;

    let read_stream = stream.try_clone()?;
    let mut write_stream = stream;
    let session_alive = Arc::new(AtomicBool::new(true));
    let alive_for_writer = session_alive.clone();

    // Reader thread: socket -> stdout. Runs until socket EOF.
    let reader = thread::spawn(move || {
        let mut sock = read_stream;
        let mut buf = [0_u8; 4096];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => {
                    alive_for_writer.store(false, Ordering::SeqCst);
                    break;
                }
                Ok(n) => {
                    let _ = std::io::stdout().write_all(&buf[..n]);
                    let _ = std::io::stdout().flush();
                }
                Err(_) => {
                    alive_for_writer.store(false, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    // Main thread: stdin -> socket. Runs until stdin EOF or session_alive=false.
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut buf = [0_u8; 4096];
    while session_alive.load(Ordering::SeqCst) {
        match handle.read(&mut buf) {
            Ok(0) => {
                let _ = write_stream.shutdown(Shutdown::Write);
                break;
            }
            Ok(n) => {
                if write_stream.write_all(&buf[..n]).is_err() {
                    break;
                }
                let _ = write_stream.flush();
            }
            Err(_) => break,
        }
    }

    let _ = write_stream.shutdown(Shutdown::Both);
    let _ = reader.join();
    eprintln!("cornela-offsec: session closed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_kind() {
        let result = run(ListenerOptions {
            kind: "udp",
            bind: "127.0.0.1",
            port: 0,
            once: true,
            timeout_secs: 1,
        });
        assert!(result.is_err());
    }

    #[test]
    fn timeout_with_no_connection_returns_report_with_error() {
        // Use port 0 to let the OS pick a free port, then we never connect.
        let result = run(ListenerOptions {
            kind: "tcp",
            bind: "127.0.0.1",
            port: 0,
            once: true,
            timeout_secs: 1,
        });
        match result {
            Ok(report) => {
                assert_eq!(report.sessions, 0);
                assert!(report.error.is_some());
            }
            Err(err) => {
                assert!(
                    err.contains("bind failed"),
                    "unexpected listener error in restricted environment: {err}"
                );
            }
        }
    }
}
