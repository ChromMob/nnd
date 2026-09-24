use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cwd = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let tp = cwd.join("third_party");
    let script = tp.join("build-opcodes.sh");
    let opcodes_out = tp.join("opcodes-out");

    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rerun-if-changed={}", tp.join("nnd_disasm.c").display());
    println!("cargo:rerun-if-changed={}", tp.join("nnd_disasm.h").display());
    println!("cargo:rerun-if-changed={}", cwd.join("Cargo.toml").display());
    println!("cargo:rerun-if-changed={}", cwd.join("build.rs").display());

    // Build libopcodes if the stamp is missing/stale (script self-checks).
    let status = Command::new("bash")
        .arg(&script)
        .current_dir(&cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", script.display()));
    if !status.success() {
        panic!(
            "{} failed with {status}; see output above",
            script.display()
        );
    }

    let include = opcodes_out.join("include");
    println!("cargo:rustc-link-search=native={}", opcodes_out.display());
    // Link order: opcodes depends on bfd/sframe/iberty/z.
    println!("cargo:rustc-link-lib=static=opcodes");
    println!("cargo:rustc-link-lib=static=bfd");
    if opcodes_out.join("libsframe.a").exists() {
        println!("cargo:rustc-link-lib=static=sframe");
    }
    if opcodes_out.join("libz.a").exists() {
        println!("cargo:rustc-link-lib=static=z");
    }
    println!("cargo:rustc-link-lib=static=iberty");
    println!("cargo:rustc-link-lib=dylib=z");
    println!("cargo:rustc-link-lib=dylib=zstd");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=dl");

    let mut build = cc::Build::new();
    build
        .file(tp.join("nnd_disasm.c"))
        .include(&include)
        .include(&tp)
        .warnings(false);
    // Some binutils headers are C99 with GNU extensions.
    build.flag_if_supported("-std=gnu11");
    build.compile("nnd_disasm");

    // Keep OUT_DIR referenced so rebuilds notice (object lands there).
    let _ = out_dir;
}
