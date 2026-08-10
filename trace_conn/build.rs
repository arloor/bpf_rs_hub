use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/tracecon.bpf.c";

fn main() {
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set"));
    let vmlinux_dir = manifest_dir
        .parent()
        .expect("trace_conn must be inside the workspace root");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("tracecon.skel.rs");
    let mut builder = SkeletonBuilder::new();
    let builder = builder
        .source(SRC)
        .clang_args([OsStr::new("-I"), vmlinux_dir.as_os_str()]);
    builder.build_and_generate(&out).unwrap();
    println!("cargo:rerun-if-changed={SRC}");
    println!(
        "cargo:rerun-if-changed={}",
        vmlinux_dir.join("vmlinux.h").display()
    );
}
