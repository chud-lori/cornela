mod audit;
mod cli;
mod container;
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
        } => {
            let status = monitor::preflight(duration_seconds);
            match output {
                OutputMode::Text => report::print_monitor_status(&status),
                OutputMode::Json => println!("{}", json::monitor_status_to_json(&status)),
            }
            Ok(())
        }
        Command::Help => {
            cli::print_help();
            Ok(())
        }
    }
}
