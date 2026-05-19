// Kubernetes recon. Read-only, uses only the service-account token already
// mounted into the pod. We shell out to `curl` to talk to the API server
// rather than pulling in a TLS dependency — this keeps the crate dep-free
// and matches the tools red-teamers already have on Kali.
//
// What this does:
//   - decodes the JWT in the SA token to extract the service account name,
//     namespace, and any audience claims (no API call required for whoami)
//   - issues a SelfSubjectRulesReview against the API server to enumerate
//     what the SA is permitted to do in its own namespace
//   - lists secrets/pods/configmaps in the SA's namespace
//
// All operations are read-only. We never POST/PATCH cluster resources.

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

const SA_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

#[derive(Debug, Clone, Default)]
pub struct K8sReport {
    pub in_cluster: bool,
    pub api_server: Option<String>,
    pub service_account: Option<JwtClaims>,
    pub permissions: Option<RulesReview>,
    pub namespace_secrets: Option<ListSummary>,
    pub namespace_pods: Option<ListSummary>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct JwtClaims {
    pub raw_subject: Option<String>,
    pub service_account_name: Option<String>,
    pub service_account_namespace: Option<String>,
    pub audiences: Vec<String>,
    pub expiry_unix: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct RulesReview {
    pub resource_rules: Vec<String>,
    pub non_resource_rules: Vec<String>,
    pub incomplete: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ListSummary {
    pub kind: &'static str,
    pub count: usize,
    pub names: Vec<String>,
    pub error: Option<String>,
}

pub fn collect() -> K8sReport {
    let mut report = K8sReport::default();
    let token_path = format!("{SA_DIR}/token");
    let token_present = Path::new(&token_path).exists();
    let api_host = env::var("KUBERNETES_SERVICE_HOST").ok();
    let api_port = env::var("KUBERNETES_SERVICE_PORT").ok();

    report.in_cluster = token_present && api_host.is_some();
    report.api_server = match (&api_host, &api_port) {
        (Some(host), Some(port)) => Some(format!("https://{host}:{port}")),
        (Some(host), None) => Some(format!("https://{host}:443")),
        _ => None,
    };

    if !token_present {
        report
            .notes
            .push("no service account token at default path; not running in-cluster".to_string());
        return report;
    }

    let token = match fs::read_to_string(&token_path) {
        Ok(value) => value.trim().to_string(),
        Err(err) => {
            report.notes.push(format!("token unreadable: {err}"));
            return report;
        }
    };

    report.service_account = decode_jwt_claims(&token);

    let namespace = report
        .service_account
        .as_ref()
        .and_then(|c| c.service_account_namespace.clone())
        .or_else(|| {
            fs::read_to_string(format!("{SA_DIR}/namespace"))
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        });

    let api_server = match &report.api_server {
        Some(url) => url.clone(),
        None => {
            report
                .notes
                .push("KUBERNETES_SERVICE_HOST not set; skipping API calls".to_string());
            return report;
        }
    };

    if !curl_available() {
        report
            .notes
            .push("curl not found in PATH; skipping API calls".to_string());
        return report;
    }

    if let Some(ns) = &namespace {
        report.permissions = run_self_subject_rules_review(&api_server, &token, ns);
        report.namespace_secrets = Some(list_namespaced(
            &api_server,
            &token,
            ns,
            "secrets",
            "secrets",
        ));
        report.namespace_pods = Some(list_namespaced(&api_server, &token, ns, "pods", "pods"));
    } else {
        report
            .notes
            .push("could not determine SA namespace; skipping namespace listings".to_string());
    }

    report
}

fn curl_available() -> bool {
    Command::new("curl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn decode_jwt_claims(token: &str) -> Option<JwtClaims> {
    // JWT format: header.payload.signature — all base64url-encoded. We only
    // care about the payload, and only need a small subset of the claims.
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    let payload = base64url_decode(payload_b64).ok()?;
    let payload_str = String::from_utf8_lossy(&payload).into_owned();

    let sub = json_string_field(&payload_str, "sub");
    let exp = json_number_field(&payload_str, "exp");
    let aud_singular = json_string_field(&payload_str, "aud");
    let aud_array = json_string_array_field(&payload_str, "aud");
    let mut audiences = aud_array;
    if audiences.is_empty() {
        if let Some(value) = aud_singular {
            audiences.push(value);
        }
    }

    // Service account JWTs follow the pattern:
    //   sub = "system:serviceaccount:<namespace>:<name>"
    let (sa_namespace, sa_name) = sub
        .as_deref()
        .and_then(parse_service_account_subject)
        .map(|(ns, name)| (Some(ns), Some(name)))
        .unwrap_or((None, None));

    Some(JwtClaims {
        raw_subject: sub,
        service_account_name: sa_name,
        service_account_namespace: sa_namespace,
        audiences,
        expiry_unix: exp,
    })
}

fn parse_service_account_subject(subject: &str) -> Option<(String, String)> {
    let rest = subject.strip_prefix("system:serviceaccount:")?;
    let mut parts = rest.splitn(2, ':');
    let namespace = parts.next()?.to_string();
    let name = parts.next()?.to_string();
    Some((namespace, name))
}

fn run_self_subject_rules_review(
    api_server: &str,
    token: &str,
    namespace: &str,
) -> Option<RulesReview> {
    let body = format!(
        r#"{{"kind":"SelfSubjectRulesReview","apiVersion":"authorization.k8s.io/v1","spec":{{"namespace":"{namespace}"}}}}"#
    );
    let url = format!("{api_server}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews");
    let body = match curl_post(&url, token, &body) {
        Ok(text) => text,
        Err(_err) => return None,
    };
    Some(parse_rules_review(&body))
}

fn list_namespaced(
    api_server: &str,
    token: &str,
    namespace: &str,
    resource: &str,
    label: &'static str,
) -> ListSummary {
    let url = format!("{api_server}/api/v1/namespaces/{namespace}/{resource}");
    match curl_get(&url, token) {
        Ok(text) => {
            let names = extract_metadata_names(&text);
            ListSummary {
                kind: label,
                count: names.len(),
                names,
                error: None,
            }
        }
        Err(err) => ListSummary {
            kind: label,
            count: 0,
            names: Vec::new(),
            error: Some(err),
        },
    }
}

fn curl_get(url: &str, token: &str) -> Result<String, String> {
    let ca_path = format!("{SA_DIR}/ca.crt");
    let auth = format!("Authorization: Bearer {token}");
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "5",
            "--cacert",
            &ca_path,
            "-H",
            &auth,
            url,
        ])
        .output()
        .map_err(|err| format!("curl invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn curl_post(url: &str, token: &str, body: &str) -> Result<String, String> {
    let ca_path = format!("{SA_DIR}/ca.crt");
    let auth = format!("Authorization: Bearer {token}");
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "5",
            "--cacert",
            &ca_path,
            "-H",
            &auth,
            "-H",
            "Content-Type: application/json",
            "-X",
            "POST",
            "--data",
            body,
            url,
        ])
        .output()
        .map_err(|err| format!("curl invocation failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// Conservative-but-readable rules-review parser. The real response is a
// nested JSON document; we extract the human-meaningful summary lines
// without pulling in serde. Format example (abbreviated):
//   {"status":{"resourceRules":[{"verbs":["get","list"],"resources":["pods"]}],
//              "nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/healthz"]}],
//              "incomplete":false}}
fn parse_rules_review(body: &str) -> RulesReview {
    let mut review = RulesReview {
        incomplete: body.contains("\"incomplete\":true"),
        ..RulesReview::default()
    };

    for rule in extract_object_array(body, "resourceRules") {
        let verbs = extract_string_array(&rule, "verbs").join(",");
        let resources = extract_string_array(&rule, "resources").join(",");
        let api_groups = extract_string_array(&rule, "apiGroups").join(",");
        let resource_names = extract_string_array(&rule, "resourceNames").join(",");
        let mut line = format!("[{verbs}] {api_groups}/{resources}");
        if !resource_names.is_empty() {
            line.push_str(&format!(" names={resource_names}"));
        }
        review.resource_rules.push(line);
    }

    for rule in extract_object_array(body, "nonResourceRules") {
        let verbs = extract_string_array(&rule, "verbs").join(",");
        let urls = extract_string_array(&rule, "nonResourceURLs").join(",");
        review.non_resource_rules.push(format!("[{verbs}] {urls}"));
    }

    review
}

// Walk a flat key/value style JSON document for "metadata":{"name":"<x>"}.
// Returns names in document order.
fn extract_metadata_names(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let needle = b"\"metadata\":{";
    let mut idx = 0;
    while idx + needle.len() <= bytes.len() {
        if &bytes[idx..idx + needle.len()] == needle {
            let after = &body[idx + needle.len()..];
            if let Some(name) = json_string_field(after, "name") {
                out.push(name);
            }
            idx += needle.len();
        } else {
            idx += 1;
        }
    }
    out
}

// ---- minimal JSON extraction (no serde) ----

fn json_string_field(text: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":");
    let value = text.split(&needle).nth(1)?.trim_start();
    let value = value.strip_prefix('"')?;
    // Find the closing quote, honoring backslash escapes.
    let mut chars = value.char_indices();
    let mut end = None;
    while let Some((i, ch)) = chars.next() {
        if ch == '\\' {
            chars.next();
            continue;
        }
        if ch == '"' {
            end = Some(i);
            break;
        }
    }
    let end = end?;
    Some(value[..end].to_string())
}

fn json_number_field(text: &str, field: &str) -> Option<u64> {
    let needle = format!("\"{field}\":");
    let value = text.split(&needle).nth(1)?.trim_start();
    let end = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    value[..end].parse::<u64>().ok()
}

fn json_string_array_field(text: &str, field: &str) -> Vec<String> {
    let needle = format!("\"{field}\":[");
    let Some(after) = text.split(&needle).nth(1) else {
        return Vec::new();
    };
    let Some(end) = after.find(']') else {
        return Vec::new();
    };
    parse_string_list(&after[..end])
}

fn extract_string_array(text: &str, field: &str) -> Vec<String> {
    json_string_array_field(text, field)
}

// Returns top-level object slices for a "<field>":[ {...}, {...} ] array.
// We do brace-balanced extraction so nested objects/arrays inside each
// element don't truncate. Brace balancing also tolerates strings that
// contain literal {} characters.
fn extract_object_array(text: &str, field: &str) -> Vec<String> {
    let needle = format!("\"{field}\":[");
    let Some((_, after)) = text.split_once(&needle) else {
        return Vec::new();
    };
    let bytes = after.as_bytes();
    let mut idx = 0;
    let mut depth_brackets: i32 = 1; // we just consumed the opening [
    let mut out = Vec::new();
    while idx < bytes.len() && depth_brackets > 0 {
        match bytes[idx] {
            b'{' => {
                let start = idx;
                let mut depth = 1_i32;
                let mut in_str = false;
                let mut escaped = false;
                idx += 1;
                while idx < bytes.len() && depth > 0 {
                    let b = bytes[idx];
                    if in_str {
                        if escaped {
                            escaped = false;
                        } else if b == b'\\' {
                            escaped = true;
                        } else if b == b'"' {
                            in_str = false;
                        }
                    } else {
                        match b {
                            b'"' => in_str = true,
                            b'{' => depth += 1,
                            b'}' => depth -= 1,
                            _ => {}
                        }
                    }
                    idx += 1;
                }
                let slice = &after[start..idx];
                out.push(slice.to_string());
            }
            b']' => {
                depth_brackets -= 1;
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    out
}

fn parse_string_list(slice: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_str = false;
    let mut escaped = false;
    let mut current = String::new();
    for ch in slice.chars() {
        if in_str {
            if escaped {
                current.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                out.push(std::mem::take(&mut current));
                in_str = false;
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            in_str = true;
        }
    }
    out
}

fn base64url_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let mut translated = String::with_capacity(input.len() + 4);
    for ch in input.chars() {
        match ch {
            '-' => translated.push('+'),
            '_' => translated.push('/'),
            '=' => translated.push('='),
            other if other.is_ascii_alphanumeric() || other == '+' || other == '/' => {
                translated.push(other)
            }
            _ => return Err("invalid base64url character"),
        }
    }
    while translated.len() % 4 != 0 {
        translated.push('=');
    }
    base64_decode_std(&translated)
}

// Hand-rolled standard-alphabet base64 decoder. We only use this for JWT
// payload decoding (small input), so a 4-byte-at-a-time loop is fine.
fn base64_decode_std(input: &str) -> Result<Vec<u8>, &'static str> {
    let table: [i8; 256] = {
        let mut t = [-1_i8; 256];
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < alphabet.len() {
            t[alphabet[i] as usize] = i as i8;
            i += 1;
        }
        t
    };
    let bytes = input.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err("invalid base64 length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = bytes[i + 1];
        let b2 = bytes[i + 2];
        let b3 = bytes[i + 3];
        let v0 = decode_byte(table, b0)?;
        let v1 = decode_byte(table, b1)?;
        out.push((v0 << 2) | (v1 >> 4));
        if b2 != b'=' {
            let v2 = decode_byte(table, b2)?;
            out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
            if b3 != b'=' {
                let v3 = decode_byte(table, b3)?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
        i += 4;
    }
    Ok(out)
}

fn decode_byte(table: [i8; 256], byte: u8) -> Result<u8, &'static str> {
    let value = table[byte as usize];
    if value < 0 {
        Err("invalid base64 byte")
    } else {
        Ok(value as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_service_account_subject() {
        assert_eq!(
            parse_service_account_subject("system:serviceaccount:my-ns:my-sa"),
            Some(("my-ns".to_string(), "my-sa".to_string()))
        );
        assert_eq!(parse_service_account_subject("system:node:foo"), None);
    }

    #[test]
    fn decodes_jwt_payload() {
        // {"sub":"system:serviceaccount:default:demo","aud":["api"],"exp":1234567890}
        // header.payload.signature
        let payload =
            r#"{"sub":"system:serviceaccount:default:demo","aud":["api"],"exp":1234567890}"#;
        let payload_b64 = base64url_encode(payload.as_bytes());
        let token = format!("eyJhbGciOiJSUzI1NiJ9.{payload_b64}.deadbeef");
        let claims = decode_jwt_claims(&token).expect("decode");
        assert_eq!(claims.service_account_name, Some("demo".to_string()));
        assert_eq!(
            claims.service_account_namespace,
            Some("default".to_string())
        );
        assert_eq!(claims.audiences, vec!["api".to_string()]);
        assert_eq!(claims.expiry_unix, Some(1234567890));
    }

    #[test]
    fn extract_metadata_names_returns_in_order() {
        let body = r#"{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b","extra":"x"}}]}"#;
        assert_eq!(
            extract_metadata_names(body),
            vec!["a".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn parse_rules_review_extracts_resource_rules() {
        let body = r#"{"status":{"resourceRules":[{"verbs":["get","list"],"resources":["pods","secrets"],"apiGroups":[""]}],"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/healthz"]}],"incomplete":false}}"#;
        let review = parse_rules_review(body);
        assert!(!review.incomplete);
        assert_eq!(review.resource_rules.len(), 1);
        assert!(review.resource_rules[0].contains("pods,secrets"));
        assert_eq!(review.non_resource_rules.len(), 1);
        assert!(review.non_resource_rules[0].contains("/healthz"));
    }

    fn base64url_encode(input: &[u8]) -> String {
        // Tiny encoder used only by the test above. We do not need this in
        // production code — JWTs are an input to the offsec tool, not an
        // output.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let mut i = 0;
        while i + 3 <= input.len() {
            let b = &input[i..i + 3];
            out.push(alphabet[(b[0] >> 2) as usize] as char);
            out.push(alphabet[(((b[0] & 0x03) << 4) | (b[1] >> 4)) as usize] as char);
            out.push(alphabet[(((b[1] & 0x0f) << 2) | (b[2] >> 6)) as usize] as char);
            out.push(alphabet[(b[2] & 0x3f) as usize] as char);
            i += 3;
        }
        let remaining = input.len() - i;
        if remaining == 1 {
            let b0 = input[i];
            out.push(alphabet[(b0 >> 2) as usize] as char);
            out.push(alphabet[((b0 & 0x03) << 4) as usize] as char);
        } else if remaining == 2 {
            let b0 = input[i];
            let b1 = input[i + 1];
            out.push(alphabet[(b0 >> 2) as usize] as char);
            out.push(alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(alphabet[((b1 & 0x0f) << 2) as usize] as char);
        }
        out
    }

    #[test]
    fn round_trip_base64url() {
        let payload = b"{\"sub\":\"x\"}";
        let encoded = base64url_encode(payload);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, payload);
    }
}
