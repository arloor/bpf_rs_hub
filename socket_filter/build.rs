use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/program.bpf.c";

fn main() {
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set in build script"))
        .join("program.skel.rs");
    let mut builder = SkeletonBuilder::new();
    let builder = builder.source(SRC);
    builder.clang_args(["-I."]);
    builder.build_and_generate(&out).unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
