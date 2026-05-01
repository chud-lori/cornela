mod audit;
mod cli;
mod container;
mod json;
mod report;
mod risk;

use std::process::ExitCode;

use cli::{Command, OutputMode};

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
            std::fs::write(&output, json::report_to_json(&report))
                .map_err(|err| format!("failed to write {output}: {err}"))?;
            println!("wrote {output}");
            Ok(())
        }
        Command::Monitor { output } => {
            report::print_monitor_placeholder(output);
            Ok(())
        }
        Command::Help => {
            cli::print_help();
            Ok(())
        }
    }
}
