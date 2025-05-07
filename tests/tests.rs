use std::fs;
use std::process::{self, Command};

use rustc_version::VersionMeta;
use tempfile::tempdir;

use rustc_build_sysroot::*;

fn run(cmd: &mut Command) {
    assert!(cmd
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .expect("failed to run {cmd:?}")
        .success());
}

fn build_sysroot(b: SysrootBuilder) {
    let src_dir = rustc_sysroot_src(Command::new("rustc")).unwrap();
    b.cargo(Command::new("cargo"))
        .build_from_source(&src_dir)
        .unwrap();
}

fn test_sysroot_build(target: &str, mode: BuildMode, rustc_version: &VersionMeta) {
    let sysroot_dir = tempdir().unwrap();
    build_sysroot(
        SysrootBuilder::new(sysroot_dir.path(), target)
            .build_mode(mode)
            .rustc_version(rustc_version.clone()),
    );

    let crate_name = "rustc-build-sysroot-test-crate";
    let crate_dir = tempdir().unwrap();
    run(Command::new("cargo")
        .args(["new", crate_name])
        .current_dir(&crate_dir));
    let crate_dir = crate_dir.path().join(crate_name);
    run(Command::new("cargo")
        .arg(mode.as_str())
        .arg("--target")
        .arg(target)
        .current_dir(&crate_dir)
        .env(
            "RUSTFLAGS",
            format!("--sysroot {}", sysroot_dir.path().display()),
        ));
    if mode == BuildMode::Build && target == rustc_version.host {
        run(Command::new("cargo")
            .arg("run")
            .current_dir(&crate_dir)
            .env(
                "RUSTFLAGS",
                format!("--sysroot {}", sysroot_dir.path().display()),
            ));
    }
}

#[test]
fn host() {
    let rustc_version = VersionMeta::for_command(Command::new("rustc")).unwrap();

    for mode in [BuildMode::Build, BuildMode::Check] {
        test_sysroot_build(&rustc_version.host, mode, &rustc_version);
    }
}

#[test]
fn cross() {
    let rustc_version = VersionMeta::for_command(Command::new("rustc")).unwrap();

    // Cover three CPU architectures and three OSes.
    for target in [
        "i686-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
    ] {
        test_sysroot_build(target, BuildMode::Check, &rustc_version);
    }
}

#[test]
fn no_std() {
    let sysroot_dir = tempdir().unwrap();
    build_sysroot(
        SysrootBuilder::new(sysroot_dir.path(), "thumbv7em-none-eabihf")
            .build_mode(BuildMode::Check)
            .sysroot_config(SysrootConfig::NoStd),
    );
}

#[test]
fn json_target() {
    let target = r#"{
        "llvm-target": "x86_64-unknown-none",
        "target-endian": "little",
        "target-pointer-width": "64",
        "target-c-int-width": "32",
        "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
        "arch": "x86_64",
        "os": "none",
        "env": "",
        "vendor": "unknown",
        "linker": "rust-lld",
        "linker-flavor": "gnu-lld",
        "rustc-abi": "x86-softfloat",
        "features": "-mmx,-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-avx,-avx2,+soft-float",
        "dynamic-linking": false,
        "executables": true,
        "relocation-model": "static",
        "code-model": "kernel",
        "disable-redzone": true,
        "frame-pointer": "always",
        "exe-suffix": "",
        "has-rpath": false,
        "no-default-libraries": true,
        "position-independent-executables": false
    }"#;

    let sysroot_dir = tempdir().unwrap();
    let target_file = sysroot_dir.path().join("mytarget.json");
    fs::write(&target_file, target).unwrap();

    build_sysroot(
        SysrootBuilder::new(sysroot_dir.path(), &target_file)
            .build_mode(BuildMode::Check)
            .sysroot_config(SysrootConfig::NoStd),
    );
}
