//! dae-rs build script
//!
//! Compile C eBPF code (tproxy.c) to BPF bytecode file (ebpf.o),
//! then copy it to OUT_DIR for the main program to embed via include_bytes!.
//!
//! Requires: clang (≥14), llvm-strip, Git submodule initialized

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // eBPF source code path
    let kern_dir = manifest_dir.join("bpf/kern");
    let headers_dir = kern_dir.join("headers");
    let tproxy_c = kern_dir.join("tproxy.c");
    let output_obj = out_dir.join("ebpf.o");

    // Tell cargo to re-run when these files change
    println!("cargo:rerun-if-changed=bpf/kern/tproxy.c");
    println!("cargo:rerun-if-changed=bpf/kern/ebpf_sync_defs.h");
    println!("cargo:rerun-if-changed=bpf/kern/headers");

    // Check if tproxy.c exists (submodule must be initialized)
    assert!(
        tproxy_c.exists(),
        "tproxy.c not found at {}. Run `git submodule update --init` first.",
        tproxy_c.display()
    );

    // Get tool paths from environment variables or defaults
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".to_string());
    let llvm_strip = env::var("LLVM_STRIP").unwrap_or_else(|_| "llvm-strip".to_string());
    let max_match_set_len =
        env::var("MAX_MATCH_SET_LEN").unwrap_or_else(|_| "1024".to_string());

    // Compile tproxy.c → ebpf.o
    let cflags = [
        "-O2",
        "-Wall",
        "-Werror",
        "-target",
        "bpf",
        "-g",
        &format!("-DMAX_MATCH_SET_LEN={}", max_match_set_len),
        "-I",
        headers_dir.to_str().unwrap(),
        "-I",
        kern_dir.to_str().unwrap(),
        "-c",
        tproxy_c.to_str().unwrap(),
        "-o",
        output_obj.to_str().unwrap(),
    ];

    println!(
        "cargo:warning=Compiling eBPF: {} {}",
        clang,
        cflags.join(" ")
    );

    let status = Command::new(&clang)
        .args(cflags)
        .status()
        .expect("Failed to execute clang. Is clang (≥14) installed?");

    assert!(
        status.success(),
        "clang eBPF compilation failed. Check clang installation."
    );

    // Strip debug info (keep BTF info for CO-RE support)
    let strip_status = Command::new(&llvm_strip)
        .args(["-g", output_obj.to_str().unwrap()])
        .status();

    match strip_status {
        Ok(status) if status.success() => {
            println!("cargo:warning=eBPF bytecode stripped (BTF preserved)");
        }
        _ => {
            println!("cargo:warning=llvm-strip not found or failed; debug info preserved");
        }
    }

    println!(
        "cargo:warning=eBPF bytecode compiled from tproxy.c -> {}",
        output_obj.display()
    );
}
