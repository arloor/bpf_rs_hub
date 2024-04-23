use std::env;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/tracecon.bpf.c";

fn main() {
    let out = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script"),
    )
    .join("src")
    .join("bpf")
    .join("tracecon.skel.rs");
    let mut builder = SkeletonBuilder::new();
    let builder = builder.source(SRC);
    // 使用本地的vmlinux.h
    // builder.clang_args(["-I."]);
    {
        use std::ffi::OsStr;
        let arch = env::var("CARGO_CFG_TARGET_ARCH")
        .expect("CARGO_CFG_TARGET_ARCH must be set in build script");
        builder.clang_args([
            OsStr::new("-I"),
            vmlinux::include_path_root().join(arch).as_os_str(),
        ]);
    }
    builder.build_and_generate(&out).unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
