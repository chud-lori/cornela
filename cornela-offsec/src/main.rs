use std::process::ExitCode;

mod breakout;
mod cli;
mod escalate;
mod exploit;
mod k8s;
mod listener;
mod output;
mod payload;
mod pivot;
mod proc;
mod recon;
mod signals;
mod vectors;
mod vuln_check;

fn main() -> ExitCode {
    match cli::parse(std::env::args().skip(1).collect()) {
        cli::Action::Help => {
            print!("{}", cli::HELP);
            ExitCode::SUCCESS
        }
        cli::Action::Version => {
            println!("cornela-offsec {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        cli::Action::Enum { json } => run_enum(json),
        cli::Action::Vectors { json } => run_vectors(json),
        cli::Action::VulnCheck { cve, json } => run_vuln_check(&cve, json),
        cli::Action::Signals {
            pattern,
            count,
            json,
        } => run_signals(&pattern, count, json),
        cli::Action::Kubernetes { json } => run_k8s(json),
        cli::Action::Breakout {
            technique,
            command,
            execute,
            json,
        } => run_breakout(&technique, &command, execute, json),
        cli::Action::Pivot {
            technique,
            command,
            as_user,
            target_container,
            execute,
            json,
        } => run_pivot(
            &technique,
            &command,
            as_user.as_deref(),
            target_container.as_deref(),
            execute,
            json,
        ),
        cli::Action::Exploit {
            poc,
            target_cve,
            timeout_secs,
            check_host_file,
            execute,
            json,
        } => run_exploit(
            &poc,
            target_cve.as_deref(),
            timeout_secs,
            check_host_file.as_deref(),
            execute,
            json,
        ),
        cli::Action::Escalate { action, json } => run_escalate(&action, json),
        cli::Action::Payload { kind, lang, to } => run_payload(&kind, &lang, to.as_deref()),
        cli::Action::Listener {
            kind,
            bind,
            port,
            once,
            timeout_secs,
        } => run_listener(&kind, &bind, port, once, timeout_secs),
        cli::Action::Error(message) => {
            eprintln!("cornela-offsec: {message}");
            eprintln!();
            eprint!("{}", cli::HELP);
            ExitCode::from(2)
        }
    }
}

fn run_enum(json: bool) -> ExitCode {
    let recon = recon::collect();
    if json {
        println!("{}", output::recon_to_json(&recon));
    } else {
        output::recon_to_human(&recon, &mut std::io::stdout());
    }
    ExitCode::SUCCESS
}

fn run_vectors(json: bool) -> ExitCode {
    let recon = recon::collect();
    let evaluated = vectors::evaluate_all(&recon);
    if json {
        println!("{}", output::vectors_to_json(&evaluated));
    } else {
        output::vectors_to_human(&evaluated, &mut std::io::stdout());
    }
    ExitCode::SUCCESS
}

fn run_vuln_check(cve: &str, json: bool) -> ExitCode {
    match vuln_check::check(cve) {
        Ok(report) => {
            if json {
                println!("{}", output::vuln_to_json(&report));
            } else {
                output::vuln_to_human(&report, &mut std::io::stdout());
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_signals(pattern: &str, count: u32, json: bool) -> ExitCode {
    match signals::run(pattern, count) {
        Ok(report) => {
            if json {
                println!("{}", output::signals_to_json(&report));
            } else {
                output::signals_to_human(&report, &mut std::io::stdout());
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_k8s(json: bool) -> ExitCode {
    let report = k8s::collect();
    if json {
        println!("{}", output::k8s_to_json(&report));
    } else {
        output::k8s_to_human(&report, &mut std::io::stdout());
    }
    ExitCode::SUCCESS
}

fn run_breakout(technique: &str, command: &str, execute: bool, json: bool) -> ExitCode {
    if execute {
        eprintln!(
            "cornela-offsec: BREAKOUT '{technique}' --execute set; this will attempt host-side actions."
        );
    }
    match breakout::run(technique, command, execute) {
        Ok(outcome) => {
            if json {
                println!("{}", output::breakout_to_json(&outcome));
            } else {
                output::breakout_to_human(&outcome, &mut std::io::stdout());
            }
            if outcome.executed && !outcome.success {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_pivot(
    technique: &str,
    command: &str,
    as_user: Option<&str>,
    target_container: Option<&str>,
    execute: bool,
    json: bool,
) -> ExitCode {
    match pivot::run(technique, command, as_user, target_container, execute) {
        Ok(outcome) => {
            if json {
                println!("{}", output::pivot_to_json(&outcome));
            } else {
                output::pivot_to_human(&outcome, &mut std::io::stdout());
            }
            if outcome.executed && !outcome.success {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_exploit(
    poc: &str,
    target_cve: Option<&str>,
    timeout_secs: u64,
    check_host_file: Option<&str>,
    execute: bool,
    json: bool,
) -> ExitCode {
    match exploit::run(exploit::ExploitOptions {
        poc_path: poc,
        target_cve,
        timeout_secs,
        check_host_file,
        execute,
    }) {
        Ok(report) => {
            if json {
                println!("{}", output::exploit_to_json(&report));
            } else {
                output::exploit_to_human(&report, &mut std::io::stdout());
            }
            match report.verdict {
                exploit::Verdict::Vulnerable => ExitCode::SUCCESS,
                exploit::Verdict::DryRun | exploit::Verdict::Inconclusive => ExitCode::from(1),
                exploit::Verdict::NotExecuted | exploit::Verdict::NotVulnerable => {
                    ExitCode::from(1)
                }
            }
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_escalate(action: &str, json: bool) -> ExitCode {
    if action != "enum" {
        eprintln!("cornela-offsec: unknown escalate action '{action}' — supported: enum");
        return ExitCode::from(2);
    }
    let report = escalate::enumerate();
    if json {
        println!("{}", output::escalate_to_json(&report));
    } else {
        output::escalate_to_human(&report, &mut std::io::stdout());
    }
    ExitCode::SUCCESS
}

fn run_payload(kind: &str, lang: &str, to: Option<&str>) -> ExitCode {
    match payload::generate(payload::PayloadOptions { kind, lang, to }) {
        Ok(report) => {
            println!("{}", report.payload);
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}

fn run_listener(kind: &str, bind: &str, port: u16, once: bool, timeout_secs: u64) -> ExitCode {
    match listener::run(listener::ListenerOptions {
        kind,
        bind,
        port,
        once,
        timeout_secs,
    }) {
        Ok(report) => {
            output::listener_to_human(&report, &mut std::io::stdout());
            if report.error.is_some() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(message) => {
            eprintln!("cornela-offsec: {message}");
            ExitCode::from(2)
        }
    }
}
