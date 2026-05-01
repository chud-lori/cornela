#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputMode {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Audit {
        output: OutputMode,
    },
    Containers {
        output: OutputMode,
    },
    Report {
        output: String,
    },
    Monitor {
        output: OutputMode,
        duration_seconds: Option<u64>,
    },
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
        "monitor" => parse_monitor(args),
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

fn parse_monitor<I>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = String>,
{
    let mut output = OutputMode::Text;
    let mut duration_seconds = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => output = OutputMode::Json,
            "--text" => output = OutputMode::Text,
            "--duration" => {
                let Some(value) = args.next() else {
                    return Err("--duration requires seconds".to_string());
                };
                duration_seconds = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| format!("invalid duration seconds: {value}"))?,
                );
            }
            "--help" | "-h" => {
                return Ok(Args {
                    command: Command::Help,
                });
            }
            _ => return Err(format!("unknown monitor option: {arg}")),
        }
    }

    Ok(Args {
        command: Command::Monitor {
            output,
            duration_seconds,
        },
    })
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
  cornela monitor [--json] [--duration SECONDS]\n\
\n\
Commands:\n\
  audit       Audit host hardening and detected container risk signals\n\
  containers List container-like process groups discovered from /proc cgroups\n\
  report      Write a JSON audit report\n\
  monitor     Check runtime monitor readiness and planned eBPF probes"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Args, String> {
        parse(args.iter().map(|arg| (*arg).to_string()))
    }

    #[test]
    fn defaults_to_help_without_args() {
        assert_eq!(
            parse_args(&[]),
            Ok(Args {
                command: Command::Help
            })
        );
    }

    #[test]
    fn parses_audit_json() {
        assert_eq!(
            parse_args(&["audit", "--json"]),
            Ok(Args {
                command: Command::Audit {
                    output: OutputMode::Json
                }
            })
        );
    }

    #[test]
    fn parses_report_output_path() {
        assert_eq!(
            parse_args(&["report", "--output", "out.json"]),
            Ok(Args {
                command: Command::Report {
                    output: "out.json".to_string()
                }
            })
        );
    }

    #[test]
    fn parses_monitor_duration() {
        assert_eq!(
            parse_args(&["monitor", "--json", "--duration", "30"]),
            Ok(Args {
                command: Command::Monitor {
                    output: OutputMode::Json,
                    duration_seconds: Some(30)
                }
            })
        );
    }

    #[test]
    fn rejects_unknown_option() {
        let err = parse_args(&["audit", "--yaml"]).unwrap_err();
        assert_eq!(err, "unknown option: --yaml");
    }
}
