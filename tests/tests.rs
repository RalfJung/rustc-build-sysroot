use std::path::Path;
use std::process::{self, Command};

use rustc_version::VersionMeta;
use tempfile::TempDir;

use rustc_build_sysroot::*;

fn run(cmd: &mut Command) {
    assert!(cmd
        .stdout(process::Stdio::null())
        .stderr(process::Stdio::null())
        .status()
        .expect("failed to run {cmd:?}")
        .success());
}

fn test_sysroot_build(target: &str, mode: BuildMode, src_dir: &Path, rustc_version: &VersionMeta) {
    let sysroot_dir = TempDir::new().unwrap();
    SysrootBuilder::new(sysroot_dir.path(), target)
        .build_mode(mode)
        .rustc_version(rustc_version.clone())
        .cargo({
            let mut cmd = Command::new("cargo");
            cmd.stdout(process::Stdio::null());
            cmd.stderr(process::Stdio::null());
            cmd
        })
        .build_from_source(src_dir)
        .unwrap();

    let crate_name = "rustc-build-sysroot-test-crate";
    let crate_dir = TempDir::new().unwrap();
    run(Command::new("cargo")
        .args(&["new", crate_name])
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
    if mode == BuildMode::Build && target == &rustc_version.host {
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
    let src_dir = rustc_sysroot_src(Command::new("rustc")).unwrap();

    for mode in [BuildMode::Build, BuildMode::Check] {
        test_sysroot_build(&rustc_version.host, mode, &src_dir, &rustc_version);
    }
}

#[test]
fn cross() {
    let rustc_version = VersionMeta::for_command(Command::new("rustc")).unwrap();
    let src_dir = rustc_sysroot_src(Command::new("rustc")).unwrap();

    for target in [
        "i686-unknown-linux-gnu",
        "aarch64-apple-darwin",
        "i686-pc-windows-msvc",
    ] {
        test_sysroot_build(target, BuildMode::Check, &src_dir, &rustc_version);
    }
}

#[test]
fn no_std() {
    let src_dir = rustc_sysroot_src(Command::new("rustc")).unwrap();

    let sysroot_dir = TempDir::new().unwrap();
    SysrootBuilder::new(sysroot_dir.path(), "thumbv7em-none-eabihf")
        .build_mode(BuildMode::Check)
        .sysroot_config(SysrootConfig::NoStd)
        .cargo({
            let mut cmd = Command::new("cargo");
            cmd.stdout(process::Stdio::null());
            cmd.stderr(process::Stdio::null());
            cmd
        })
        .build_from_source(&src_dir)
        .unwrap();
}
