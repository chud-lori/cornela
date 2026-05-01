mod audit;
mod cli;
mod container;
mod cve;
mod event;
mod json;
mod monitor;
mod report;
mod risk;

use std::process::ExitCode;

use cli::{Command, OutputMode, ReportOutput};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cornela: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let args = cli::parse(std::env::args().skip(1))?;

    match args.command {
        Command::Audit { output } => {
            let audit = audit::run_host_audit();
            let containers = container::discover_containers();
            let report = report::build_report(audit, containers);
            match output {
                OutputMode::Text => report::print_host_report(&report),
                OutputMode::Json => println!("{}", json::report_to_json(&report)),
            }
            Ok(())
        }
        Command::Containers { output } => {
            let containers = container::discover_containers();
            match output {
                OutputMode::Text => report::print_containers(&containers),
                OutputMode::Json => println!("{}", json::containers_to_json(&containers)),
            }
            Ok(())
        }
        Command::Cve { id, output } => {
            let audit = audit::run_host_audit();
            let containers = container::discover_containers();
            let result = cve::scan(&id, &audit, &containers)?;
            match output {
                OutputMode::Text => report::print_cve_scan(&result),
                OutputMode::Json => println!("{}", json::cve_scan_to_json(&result)),
            }
            Ok(())
        }
        Command::Report { output } => {
            let audit = audit::run_host_audit();
            let containers = container::discover_containers();
            let report = report::build_report(audit, containers);
            let payload = json::report_to_json(&report);
            match output {
                ReportOutput::File(output) => {
                    std::fs::write(&output, payload)
                        .map_err(|err| format!("failed to write {output}: {err}"))?;
                    println!("wrote {output}");
                }
                ReportOutput::Stdout => println!("{payload}"),
            }
            Ok(())
        }
        Command::Monitor {
            output,
            duration_seconds,
            simulate,
            events,
            jsonl,
            max_events,
        } => {
            let run = monitor::run(monitor::MonitorOptions {
                duration_seconds,
                simulate,
                collect_events: events,
                jsonl,
                max_events,
            })?;
            if !jsonl {
                match output {
                    OutputMode::Text => report::print_monitor_run(&run),
                    OutputMode::Json => println!("{}", json::monitor_run_to_json(&run)),
                }
            }
            Ok(())
        }
        Command::Help => {
            cli::print_help();
            Ok(())
        }
    }
}
