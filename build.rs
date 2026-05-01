use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/monitor.bpf.c");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    let output = out_dir.join("monitor.bpf.o");
    let target_arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x86",
        Ok("aarch64") => "arm64",
        Ok("arm") => "arm",
        Ok("riscv64") => "riscv",
        Ok("powerpc64") => "powerpc",
        Ok("s390x") => "s390",
        _ => "x86",
    };
    let target_arch_define = format!("-D__TARGET_ARCH_{target_arch}");

    let status = Command::new("clang")
        .args([
            "-O2",
            "-g",
            "-target",
            "bpf",
            &target_arch_define,
            "-c",
            "bpf/monitor.bpf.c",
            "-o",
        ])
        .arg(&output)
        .status()
        .expect("failed to run clang for eBPF build");

    if !status.success() {
        panic!("failed to compile bpf/monitor.bpf.c with clang");
    }
}
