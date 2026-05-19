// Self-contained /proc parsing. Intentionally NOT shared with the parent
// cornela crate — keeping cornela-offsec extractable to its own repo.
// Only the helpers actually needed by the offsec recon are duplicated here.

use std::fs;
use std::path::PathBuf;

pub fn read_self_status() -> String {
    fs::read_to_string("/proc/self/status").unwrap_or_default()
}

pub fn read_self_mountinfo() -> String {
    fs::read_to_string("/proc/self/mountinfo").unwrap_or_default()
}

pub fn read_kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn read_loaded_modules() -> Vec<String> {
    let Ok(modules) = fs::read_to_string("/proc/modules") else {
        return Vec::new();
    };
    modules
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

pub fn read_self_cgroup() -> String {
    fs::read_to_string("/proc/self/cgroup").unwrap_or_default()
}

pub fn read_self_cmdline() -> Option<String> {
    let bytes = fs::read("/proc/self/cmdline").ok()?;
    let parts = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>();
    (!parts.is_empty()).then_some(parts.join(" "))
}

pub fn read_namespace_link(pid: u32, namespace: &str) -> Option<String> {
    let path = PathBuf::from(format!("/proc/{pid}/ns/{namespace}"));
    fs::read_link(path)
        .ok()
        .map(|target| target.to_string_lossy().to_string())
}

pub fn status_string(status: &str, key: &str) -> Option<String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_string()))
}

pub fn status_first_u64(status: &str, key: &str) -> Option<u64> {
    status_string(status, key)
        .and_then(|value| value.split_whitespace().next().map(str::to_string))
        .and_then(|value| value.parse::<u64>().ok())
}

pub fn status_u8(status: &str, key: &str) -> Option<u8> {
    status_string(status, key).and_then(|value| value.parse::<u8>().ok())
}

pub fn parse_cap_hex(status: &str, key: &str) -> Option<u64> {
    let value = status_string(status, key)?;
    u64::from_str_radix(&value, 16).ok()
}

// /proc/<pid>/mountinfo: per-mount line. Format documented in proc(5).
//
// Field layout: id, parent, dev, root, mountpoint, options [optional fields ...] - fstype source super_options
pub struct MountEntry {
    pub mount_point: String,
    pub options: String,
    pub fstype: String,
    pub source: String,
    // super_options (mountinfo column 11) is captured for future checks
    // (e.g. distinguishing rw mount vs rw remount) but unused today.
    #[allow(dead_code)]
    pub super_options: String,
}

pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields = left.split_whitespace().collect::<Vec<_>>();
        let right_fields = right.split_whitespace().collect::<Vec<_>>();
        if left_fields.len() < 6 || right_fields.len() < 3 {
            continue;
        }
        out.push(MountEntry {
            mount_point: decode_path(left_fields[4]),
            options: left_fields[5].to_string(),
            fstype: right_fields[0].to_string(),
            source: right_fields[1].to_string(),
            super_options: right_fields[2].to_string(),
        });
    }
    out
}

fn decode_path(path: &str) -> String {
    // Per proc(5): mountinfo encodes spaces and a few control chars as
    // octal escapes (\040, \011, \012, \134). Decode the common ones so
    // string compares against literal paths work.
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_string_field() {
        let status = "Name:\tnginx\nUid:\t0\t0\t0\t0\nCapEff:\t00000000a80425fb\n";
        assert_eq!(status_string(status, "Name:"), Some("nginx".to_string()));
        assert_eq!(status_first_u64(status, "Uid:"), Some(0));
        assert_eq!(parse_cap_hex(status, "CapEff:"), Some(0x00000000a80425fb));
    }

    #[test]
    fn parses_seccomp_field() {
        let status = "Seccomp:\t2\nNoNewPrivs:\t1\n";
        assert_eq!(status_u8(status, "Seccomp:"), Some(2));
        assert_eq!(status_u8(status, "NoNewPrivs:"), Some(1));
    }

    #[test]
    fn parses_mountinfo_basic() {
        let mountinfo = "1 2 0:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:2 / /proc rw - proc proc rw\n";
        let entries = parse_mountinfo(mountinfo);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].mount_point, "/");
        assert_eq!(entries[0].fstype, "ext4");
        assert_eq!(entries[0].source, "/dev/sda1");
        assert!(entries[0].options.split(',').any(|o| o == "rw"));
        assert_eq!(entries[1].mount_point, "/proc");
        assert_eq!(entries[1].fstype, "proc");
    }

    #[test]
    fn decodes_mountinfo_octal_escapes() {
        assert_eq!(
            decode_path("/path\\040with\\040spaces"),
            "/path with spaces"
        );
    }
}
