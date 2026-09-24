// Build multi-arch libopcodes (third_party/build-opcodes.sh) and the C shim.
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let tp = manifest.join("third_party");
    let out = tp.join("opcodes-out");
    let shim = tp.join("nnd_disasm.c");

    println!("cargo:rerun-if-changed={}", tp.join("build-opcodes.sh").display());
    println!("cargo:rerun-if-changed={}", shim.display());
    println!("cargo:rerun-if-changed={}", tp.join("nnd_disasm.h").display());
    println!("cargo:rerun-if-changed={}", manifest.join("Cargo.toml").display());

    let stamp = out.join(".stamp");
    if !stamp.exists() || !out.join("lib/libopcodes.a").exists() {
        let status = Command::new("bash")
            .arg(tp.join("build-opcodes.sh"))
            .current_dir(&tp)
            .status()
            .expect("failed to run third_party/build-opcodes.sh (needs curl, make, gcc)");
        if !status.success() {
            panic!("third_party/build-opcodes.sh failed with {}", status);
        }
    }

    cc::Build::new()
        .file(&shim)
        .include(&out.join("include"))
        .include(&tp)
        .flag_if_supported("-Wno-unused-parameter")
        .compile("nnd_disasm");

    let lib = out.join("lib");
    println!("cargo:rustc-link-search=native={}", lib.display());
    // Order matters: opcodes pulls from bfd, both pull iberty/z/zstd.
    println!("cargo:rustc-link-lib=static=opcodes");
    println!("cargo:rustc-link-lib=static=bfd");
    println!("cargo:rustc-link-lib=static=sframe");
    println!("cargo:rustc-link-lib=static=iberty");
    println!("cargo:rustc-link-lib=static=z");
    // zstd is only available as a shared lib on this system; bfd may need it.
    println!("cargo:rustc-link-lib=dylib=zstd");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=dl");
}
