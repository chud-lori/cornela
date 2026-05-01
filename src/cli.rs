#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Audit { output: OutputMode },
    Containers { output: OutputMode },
    Report { output: String },
    Monitor { output: OutputMode },
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub command: Command,
}

pub fn parse<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        return Ok(Args {
            command: Command::Help,
        });
    };

    match command.as_str() {
        "audit" => Ok(Args {
            command: Command::Audit {
                output: parse_output_mode(args)?,
            },
        }),
        "containers" => Ok(Args {
            command: Command::Containers {
                output: parse_output_mode(args)?,
            },
        }),
        "monitor" => Ok(Args {
            command: Command::Monitor {
                output: parse_output_mode(args)?,
            },
        }),
        "report" => {
            let mut output = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--output" | "-o" => {
                        output = args.next();
                        if output.is_none() {
                            return Err("--output requires a path".to_string());
                        }
                    }
                    "--help" | "-h" => {
                        return Ok(Args {
                            command: Command::Help,
                        });
                    }
                    _ => return Err(format!("unknown report option: {arg}")),
                }
            }

            Ok(Args {
                command: Command::Report {
                    output: output.unwrap_or_else(|| "cornela-report.json".to_string()),
                },
            })
        }
        "--help" | "-h" | "help" => Ok(Args {
            command: Command::Help,
        }),
        _ => Err(format!("unknown command: {command}")),
    }
}

fn parse_output_mode<I>(args: I) -> Result<OutputMode, String>
where
    I: IntoIterator<Item = String>,
{
    let mut output = OutputMode::Text;
    for arg in args {
        match arg.as_str() {
            "--json" => output = OutputMode::Json,
            "--text" => output = OutputMode::Text,
            "--help" | "-h" => return Ok(OutputMode::Text),
            _ => return Err(format!("unknown option: {arg}")),
        }
    }
    Ok(output)
}

pub fn print_help() {
    println!(
        "Cornela - Container Kernel Auditor for eBPF-based escape risk detection\n\
\n\
Usage:\n\
  cornela audit [--json]\n\
  cornela containers [--json]\n\
  cornela report [--output PATH]\n\
  cornela monitor [--json]\n\
\n\
Commands:\n\
  audit       Audit host hardening and detected container risk signals\n\
  containers List container-like process groups discovered from /proc cgroups\n\
  report      Write a JSON audit report\n\
  monitor     Placeholder for planned eBPF runtime monitoring"
    );
}
