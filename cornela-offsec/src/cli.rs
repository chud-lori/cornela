pub const HELP: &str = "\
cornela-offsec — offensive container/k8s recon and pentesting

USAGE:
    cornela-offsec <COMMAND> [OPTIONS]

RECON COMMANDS:
    enum                       Enumerate the current process's container/k8s attack surface
    vectors                    List which known escape techniques apply to this environment
    vuln-check <CVE>           Deterministic kernel/config check for a specific CVE
    k8s                        Kubernetes recon (SA token decode, can-i, secrets, pods)
    escalate <ACTION>          Local privilege-escalation enumeration
                                 (actions: enum)

ATTACK COMMANDS:
    signals <PATTERN>          Fire syscall signals for detection-validation
                                 (patterns: af-alg-splice)
    breakout <TECHNIQUE>       Documented container/runtime escape
                                 (techniques: release-agent, docker-sock, host-root, runc-fdleak)
                                 Default DRY-RUN; pass --execute to actually run.
    pivot <TECHNIQUE>          Post-foothold lateral movement
                                 (techniques: k8s-impersonate, k8s-sidecar, secret-harvest)
                                 Default DRY-RUN; pass --execute to actually run.
    exploit                    Run a user-supplied PoC against this host with
                                 pre/post checks (uid, hostname, host-file).
                                 Default DRY-RUN; pass --execute to actually run.
    payload <KIND>             Generate payload one-liners for clipboard/--command use
                                 (kinds: reverse-shell)
    listener tcp               Catch reverse shells on a TCP port

OPTIONS:
    --json                     Emit JSON instead of human-readable output
    --count <N>                signals: number of times to fire the pattern (default 1)
    --command <CMD>            breakout/pivot: command to run (default: id)
    --execute                  breakout/pivot/exploit: actually run, not just print plan
    --poc <PATH>               exploit: path to user-supplied PoC script
    --target-cve <CVE>         exploit: CVE label this PoC is testing (free-form)
    --timeout <SECS>           exploit/listener: max seconds to wait (default 60)
    --check-host-file <PATH>   exploit: file readable iff exploit succeeded
    --as-user <USER>           pivot k8s-impersonate: target user
    --target-container <NAME>  pivot k8s-sidecar: target container in current pod
    --lang <LANG>              payload reverse-shell: bash|sh|nc|python|perl|php (default bash)
    --to <HOST:PORT>           payload reverse-shell: callback target (required)
    --port <PORT>              listener tcp: port to bind (default 4444)
    --bind <ADDR>              listener tcp: bind address (default 0.0.0.0)
    --once                     listener: exit after first session
    -h, --help                 Show this help
    -V, --version              Show version

EXAMPLES:
    cornela-offsec enum
    cornela-offsec vuln-check CVE-2026-31431
    cornela-offsec escalate enum --json
    cornela-offsec breakout release-agent --command 'id' --execute
    cornela-offsec breakout runc-fdleak --execute
    cornela-offsec pivot secret-harvest
    cornela-offsec pivot k8s-impersonate --as-user system:masters --execute
    cornela-offsec exploit --poc ./copy_fail.py --target-cve CVE-2026-31431 --execute
    cornela-offsec payload reverse-shell --lang bash --to 10.0.0.5:4444
    cornela-offsec listener tcp --port 4444 --once

cornela-offsec is intended for authorized testing of systems you own or have
written permission to assess. The 'breakout', 'pivot', and 'exploit' commands
can take live actions against the running host when --execute is passed.
";

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Help,
    Version,
    Enum {
        json: bool,
    },
    Vectors {
        json: bool,
    },
    VulnCheck {
        cve: String,
        json: bool,
    },
    Signals {
        pattern: String,
        count: u32,
        json: bool,
    },
    Kubernetes {
        json: bool,
    },
    Breakout {
        technique: String,
        command: String,
        execute: bool,
        json: bool,
    },
    Pivot {
        technique: String,
        command: String,
        as_user: Option<String>,
        target_container: Option<String>,
        execute: bool,
        json: bool,
    },
    Exploit {
        poc: String,
        target_cve: Option<String>,
        timeout_secs: u64,
        check_host_file: Option<String>,
        execute: bool,
        json: bool,
    },
    Escalate {
        action: String,
        json: bool,
    },
    Payload {
        kind: String,
        lang: String,
        to: Option<String>,
    },
    Listener {
        kind: String,
        bind: String,
        port: u16,
        once: bool,
        timeout_secs: u64,
    },
    Error(String),
}

pub fn parse(args: Vec<String>) -> Action {
    let mut iter = args.into_iter().peekable();
    let Some(first) = iter.next() else {
        return Action::Help;
    };

    match first.as_str() {
        "-h" | "--help" | "help" => Action::Help,
        "-V" | "--version" => Action::Version,
        "enum" => parse_flag_only(iter, |json| Action::Enum { json }),
        "vectors" => parse_flag_only(iter, |json| Action::Vectors { json }),
        "vuln-check" => parse_vuln_check(iter),
        "signals" => parse_signals(iter),
        "k8s" => parse_flag_only(iter, |json| Action::Kubernetes { json }),
        "breakout" => parse_breakout(iter),
        "pivot" => parse_pivot(iter),
        "exploit" => parse_exploit(iter),
        "escalate" => parse_escalate(iter),
        "payload" => parse_payload(iter),
        "listener" => parse_listener(iter),
        other => Action::Error(format!("unknown command '{other}'")),
    }
}

fn parse_flag_only(
    args: impl Iterator<Item = String>,
    build: impl FnOnce(bool) -> Action,
) -> Action {
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    build(json)
}

fn parse_vuln_check(mut args: impl Iterator<Item = String>) -> Action {
    let Some(cve) = args.next() else {
        return Action::Error("vuln-check requires a CVE id (e.g. CVE-2026-31431)".to_string());
    };
    if cve.starts_with('-') {
        return Action::Error("vuln-check requires a CVE id before any flag".to_string());
    }
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::VulnCheck { cve, json }
}

fn parse_signals(mut args: impl Iterator<Item = String>) -> Action {
    let Some(pattern) = args.next() else {
        return Action::Error("signals requires a pattern (e.g. af-alg-splice)".to_string());
    };
    if pattern.starts_with('-') {
        return Action::Error("signals requires a pattern before any flag".to_string());
    }
    let mut count = 1_u32;
    let mut json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--count" => {
                let Some(value) = args.next() else {
                    return Action::Error("--count requires a value".to_string());
                };
                let Ok(parsed) = value.parse::<u32>() else {
                    return Action::Error(format!("invalid --count value '{value}'"));
                };
                count = parsed;
            }
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::Signals {
        pattern,
        count,
        json,
    }
}

fn parse_breakout(mut args: impl Iterator<Item = String>) -> Action {
    let Some(technique) = args.next() else {
        return Action::Error(
            "breakout requires a technique (release-agent, docker-sock, host-root)".to_string(),
        );
    };
    if technique.starts_with('-') {
        return Action::Error("breakout requires a technique before any flag".to_string());
    }
    let mut command = "id".to_string();
    let mut execute = false;
    let mut json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--command" => {
                let Some(value) = args.next() else {
                    return Action::Error("--command requires a value".to_string());
                };
                command = value;
            }
            "--execute" => execute = true,
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::Breakout {
        technique,
        command,
        execute,
        json,
    }
}

fn parse_pivot(mut args: impl Iterator<Item = String>) -> Action {
    let Some(technique) = args.next() else {
        return Action::Error(
            "pivot requires a technique (k8s-impersonate, k8s-sidecar, secret-harvest)"
                .to_string(),
        );
    };
    if technique.starts_with('-') {
        return Action::Error("pivot requires a technique before any flag".to_string());
    }
    let mut command = "id".to_string();
    let mut as_user = None;
    let mut target_container = None;
    let mut execute = false;
    let mut json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--command" => match args.next() {
                Some(v) => command = v,
                None => return Action::Error("--command requires a value".to_string()),
            },
            "--as-user" => match args.next() {
                Some(v) => as_user = Some(v),
                None => return Action::Error("--as-user requires a value".to_string()),
            },
            "--target-container" => match args.next() {
                Some(v) => target_container = Some(v),
                None => return Action::Error("--target-container requires a value".to_string()),
            },
            "--execute" => execute = true,
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::Pivot {
        technique,
        command,
        as_user,
        target_container,
        execute,
        json,
    }
}

fn parse_exploit(mut args: impl Iterator<Item = String>) -> Action {
    let mut poc: Option<String> = None;
    let mut target_cve: Option<String> = None;
    let mut timeout_secs = 60_u64;
    let mut check_host_file: Option<String> = None;
    let mut execute = false;
    let mut json = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--poc" => match args.next() {
                Some(v) => poc = Some(v),
                None => return Action::Error("--poc requires a path".to_string()),
            },
            "--target-cve" => match args.next() {
                Some(v) => target_cve = Some(v),
                None => return Action::Error("--target-cve requires a value".to_string()),
            },
            "--timeout" => match args.next() {
                Some(v) => match v.parse::<u64>() {
                    Ok(n) => timeout_secs = n,
                    Err(_) => {
                        return Action::Error(format!("invalid --timeout value '{v}'"));
                    }
                },
                None => return Action::Error("--timeout requires a value".to_string()),
            },
            "--check-host-file" => match args.next() {
                Some(v) => check_host_file = Some(v),
                None => return Action::Error("--check-host-file requires a path".to_string()),
            },
            "--execute" => execute = true,
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    let Some(poc) = poc else {
        return Action::Error("exploit requires --poc <path>".to_string());
    };
    Action::Exploit {
        poc,
        target_cve,
        timeout_secs,
        check_host_file,
        execute,
        json,
    }
}

fn parse_escalate(mut args: impl Iterator<Item = String>) -> Action {
    let Some(action) = args.next() else {
        return Action::Error("escalate requires an action (e.g. enum)".to_string());
    };
    if action.starts_with('-') {
        return Action::Error("escalate requires an action before any flag".to_string());
    }
    let mut json = false;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::Escalate { action, json }
}

fn parse_payload(mut args: impl Iterator<Item = String>) -> Action {
    let Some(kind) = args.next() else {
        return Action::Error("payload requires a kind (e.g. reverse-shell)".to_string());
    };
    if kind.starts_with('-') {
        return Action::Error("payload requires a kind before any flag".to_string());
    }
    let mut lang = "bash".to_string();
    let mut to: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--lang" => match args.next() {
                Some(v) => lang = v,
                None => return Action::Error("--lang requires a value".to_string()),
            },
            "--to" => match args.next() {
                Some(v) => to = Some(v),
                None => return Action::Error("--to requires HOST:PORT".to_string()),
            },
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::Payload { kind, lang, to }
}

fn parse_listener(mut args: impl Iterator<Item = String>) -> Action {
    let Some(kind) = args.next() else {
        return Action::Error("listener requires a kind (currently: tcp)".to_string());
    };
    if kind.starts_with('-') {
        return Action::Error("listener requires a kind before any flag".to_string());
    }
    let mut port = 4444_u16;
    let mut bind = "0.0.0.0".to_string();
    let mut once = false;
    let mut timeout_secs = 0_u64;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => match args.next() {
                Some(v) => match v.parse::<u16>() {
                    Ok(p) => port = p,
                    Err(_) => return Action::Error(format!("invalid --port value '{v}'")),
                },
                None => return Action::Error("--port requires a value".to_string()),
            },
            "--bind" => match args.next() {
                Some(v) => bind = v,
                None => return Action::Error("--bind requires an address".to_string()),
            },
            "--once" => once = true,
            "--timeout" => match args.next() {
                Some(v) => match v.parse::<u64>() {
                    Ok(t) => timeout_secs = t,
                    Err(_) => return Action::Error(format!("invalid --timeout value '{v}'")),
                },
                None => return Action::Error("--timeout requires a value".to_string()),
            },
            "-h" | "--help" => return Action::Help,
            other => return Action::Error(format!("unexpected argument '{other}'")),
        }
    }
    Action::Listener {
        kind,
        bind,
        port,
        once,
        timeout_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Action {
        parse(args.iter().map(|arg| (*arg).to_string()).collect())
    }

    #[test]
    fn no_args_shows_help() {
        assert_eq!(parse_args(&[]), Action::Help);
    }

    #[test]
    fn parses_enum_default() {
        assert_eq!(parse_args(&["enum"]), Action::Enum { json: false });
    }

    #[test]
    fn parses_enum_json() {
        assert_eq!(parse_args(&["enum", "--json"]), Action::Enum { json: true });
    }

    #[test]
    fn parses_vectors_json() {
        assert_eq!(
            parse_args(&["vectors", "--json"]),
            Action::Vectors { json: true }
        );
    }

    #[test]
    fn rejects_unknown_command() {
        assert!(matches!(parse_args(&["pwn"]), Action::Error(_)));
    }

    #[test]
    fn rejects_unexpected_arg() {
        assert!(matches!(parse_args(&["enum", "foo"]), Action::Error(_)));
    }

    #[test]
    fn parses_vuln_check_with_cve() {
        assert_eq!(
            parse_args(&["vuln-check", "CVE-2026-31431"]),
            Action::VulnCheck {
                cve: "CVE-2026-31431".to_string(),
                json: false,
            }
        );
    }

    #[test]
    fn parses_vuln_check_with_json() {
        assert_eq!(
            parse_args(&["vuln-check", "CVE-2026-31431", "--json"]),
            Action::VulnCheck {
                cve: "CVE-2026-31431".to_string(),
                json: true,
            }
        );
    }

    #[test]
    fn vuln_check_without_cve_errors() {
        assert!(matches!(parse_args(&["vuln-check"]), Action::Error(_)));
    }

    #[test]
    fn parses_signals_with_count() {
        assert_eq!(
            parse_args(&["signals", "af-alg-splice", "--count", "5"]),
            Action::Signals {
                pattern: "af-alg-splice".to_string(),
                count: 5,
                json: false,
            }
        );
    }

    #[test]
    fn signals_invalid_count_errors() {
        assert!(matches!(
            parse_args(&["signals", "af-alg-splice", "--count", "abc"]),
            Action::Error(_)
        ));
    }

    #[test]
    fn parses_k8s_default() {
        assert_eq!(parse_args(&["k8s"]), Action::Kubernetes { json: false });
    }

    #[test]
    fn parses_breakout_dry_run_default() {
        assert_eq!(
            parse_args(&["breakout", "release-agent"]),
            Action::Breakout {
                technique: "release-agent".to_string(),
                command: "id".to_string(),
                execute: false,
                json: false,
            }
        );
    }

    #[test]
    fn parses_breakout_with_execute_and_command() {
        assert_eq!(
            parse_args(&[
                "breakout",
                "docker-sock",
                "--command",
                "uname -a",
                "--execute"
            ]),
            Action::Breakout {
                technique: "docker-sock".to_string(),
                command: "uname -a".to_string(),
                execute: true,
                json: false,
            }
        );
    }

    #[test]
    fn parses_pivot_default_dry_run() {
        assert_eq!(
            parse_args(&["pivot", "secret-harvest"]),
            Action::Pivot {
                technique: "secret-harvest".to_string(),
                command: "id".to_string(),
                as_user: None,
                target_container: None,
                execute: false,
                json: false,
            }
        );
    }

    #[test]
    fn parses_pivot_with_as_user() {
        assert_eq!(
            parse_args(&[
                "pivot",
                "k8s-impersonate",
                "--as-user",
                "system:masters",
                "--execute"
            ]),
            Action::Pivot {
                technique: "k8s-impersonate".to_string(),
                command: "id".to_string(),
                as_user: Some("system:masters".to_string()),
                target_container: None,
                execute: true,
                json: false,
            }
        );
    }

    #[test]
    fn parses_exploit_required_poc() {
        assert_eq!(
            parse_args(&[
                "exploit",
                "--poc",
                "/tmp/x.py",
                "--target-cve",
                "CVE-x",
                "--execute"
            ]),
            Action::Exploit {
                poc: "/tmp/x.py".to_string(),
                target_cve: Some("CVE-x".to_string()),
                timeout_secs: 60,
                check_host_file: None,
                execute: true,
                json: false,
            }
        );
    }

    #[test]
    fn exploit_without_poc_errors() {
        assert!(matches!(parse_args(&["exploit"]), Action::Error(_)));
    }

    #[test]
    fn parses_escalate_enum() {
        assert_eq!(
            parse_args(&["escalate", "enum"]),
            Action::Escalate {
                action: "enum".to_string(),
                json: false,
            }
        );
    }

    #[test]
    fn parses_payload_reverse_shell() {
        assert_eq!(
            parse_args(&[
                "payload",
                "reverse-shell",
                "--lang",
                "bash",
                "--to",
                "10.0.0.5:4444"
            ]),
            Action::Payload {
                kind: "reverse-shell".to_string(),
                lang: "bash".to_string(),
                to: Some("10.0.0.5:4444".to_string()),
            }
        );
    }

    #[test]
    fn parses_listener_tcp_with_port() {
        assert_eq!(
            parse_args(&["listener", "tcp", "--port", "1337", "--once"]),
            Action::Listener {
                kind: "tcp".to_string(),
                bind: "0.0.0.0".to_string(),
                port: 1337,
                once: true,
                timeout_secs: 0,
            }
        );
    }
}
