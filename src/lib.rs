//! Offers an easy way to build a rustc sysroot from source.

use std::collections::hash_map::DefaultHasher;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::ops::Not;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use rustc_version::VersionMeta;
use tempdir::TempDir;

/// Returns where the given rustc stores its sysroot source code.
pub fn rustc_sysroot_src(mut rustc: Command) -> Result<PathBuf> {
    let output = rustc
        .args(["--print", "sysroot"])
        .output()
        .context("failed to determine sysroot")?;
    if !output.status.success() {
        bail!(
            "failed to determine sysroot; rustc said:\n{}",
            String::from_utf8_lossy(&output.stderr).trim_end()
        );
    }

    let sysroot =
        std::str::from_utf8(&output.stdout).context("sysroot folder is not valid UTF-8")?;
    let sysroot = Path::new(sysroot.trim_end_matches('\n'));
    Ok(sysroot
        .join("lib")
        .join("rustlib")
        .join("src")
        .join("rust")
        .join("library"))
}

/// Encode a list of rustflags for use in CARGO_ENCODED_RUSTFLAGS.
fn encode_rustflags(flags: Vec<OsString>) -> OsString {
    // Sadly `join` doesn't work for `OsString` on older rustc.
    let mut res = OsString::new();
    for flag in flags {
        if !res.is_empty() {
            res.push(OsStr::new("\x1f"));
        }
        res.push(flag);
    }
    res
}

/// The build mode to use for this sysroot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BuildMode {
    /// Do a full sysroot build. Suited for all purposes (like the regular sysroot), but only works
    /// for the host or for targets that have suitable development tools installed.
    Build,
    /// Do a check-only sysroot build. This is only suited for check-only builds of crates, but on
    /// the plus side it works for *arbitrary* targets without having any special tools installed.
    Check,
}

impl BuildMode {
    pub fn as_str(&self) -> &str {
        use BuildMode::*;
        match self {
            Build => "build",
            Check => "check",
        }
    }
}

/// Settings controlling how the sysroot will be built.
#[derive(Copy, Clone, Debug)]
pub enum SysrootConfig<'a> {
    /// Build a no-std (core-only) sysroot.
    NoStd,
    /// Build a full sysroot with the `std` and `test` crates.
    WithStd {
        /// Features to enable for the `std` crate.
        std_features: &'a [&'a str],
    },
}

/// Information about a to-be-created sysroot.
pub struct Sysroot {
    sysroot_dir: PathBuf,
    target: String,
}

/// Hash file name (in target/lib directory).
const HASH_FILE_NAME: &str = ".rustc-build-sysroot-hash";

impl Sysroot {
    /// Prepare to create a new sysroot in the given folder (that folder should later be passed to
    /// rustc via `--sysroot`), for the given target.
    pub fn new(sysroot_dir: &Path, target: &str) -> Self {
        Sysroot {
            sysroot_dir: sysroot_dir.to_owned(),
            target: target.to_owned(),
        }
    }

    fn target_dir(&self) -> PathBuf {
        self.sysroot_dir
            .join("lib")
            .join("rustlib")
            .join(&self.target)
    }

    /// Computes the hash for the sysroot, so that we know whether we have to rebuild.
    fn sysroot_compute_hash(&self, src_dir: &Path, rustc_version: &VersionMeta) -> u64 {
        let mut hasher = DefaultHasher::new();

        // For now, we just hash in the source dir and rustc commit.
        // Ideally we'd recursively hash the entire folder but that sounds slow?
        src_dir.hash(&mut hasher);
        rustc_version.commit_hash.hash(&mut hasher);

        hasher.finish()
    }

    fn sysroot_read_hash(&self) -> Option<u64> {
        let hash_file = self.target_dir().join("lib").join(HASH_FILE_NAME);
        let mut hash = String::new();
        File::open(&hash_file)
            .ok()?
            .read_to_string(&mut hash)
            .ok()?;
        hash.parse().ok()
    }

    /// Build the `self` sysroot from the given sources.
    ///
    /// `src_dir` must be the `library` source folder, i.e., the one that contains `std/Cargo.toml`.
    ///
    /// `cargo_cmd` should return a command to invoke cargo (with whatever customization is desired)
    /// and a list of rustflags to use.
    pub fn build_from_source(
        &self,
        src_dir: &Path,
        mode: BuildMode,
        config: SysrootConfig<'_>,
        rustc_version: &VersionMeta,
        cargo_cmd: impl Fn() -> (Command, Vec<OsString>),
    ) -> Result<()> {
        if !src_dir.join("std").join("Cargo.toml").exists() {
            bail!(
                "{:?} does not seem to be a rust library source folder: `src/Cargo.toml` not found",
                src_dir
            );
        }

        // Check if we even need to do anything.
        let cur_hash = self.sysroot_compute_hash(src_dir, rustc_version);
        if self.sysroot_read_hash() == Some(cur_hash) {
            // Already done!
            return Ok(());
        }

        // Prepare a workspace for cargo
        let build_dir = TempDir::new("rustc-build-sysroot").context("failed to create tempdir")?;
        let lock_file = build_dir.path().join("Cargo.lock");
        let manifest_file = build_dir.path().join("Cargo.toml");
        let lib_file = build_dir.path().join("lib.rs");
        fs::copy(
            src_dir
                .parent()
                .expect("src_dir must have a parent")
                .join("Cargo.lock"),
            &lock_file,
        )
        .context("failed to copy lockfile from sysroot source")?;
        let crates = match config {
            SysrootConfig::NoStd => format!(
                r#"
[dependencies.core]
path = {src_dir_core:?}
[dependencies.compiler_builtins]
features = ["rustc-dep-of-std", "mem"]
version = "*"
                "#,
                src_dir_core = src_dir.join("core"),
            ),
            SysrootConfig::WithStd { std_features } => format!(
                r#"
[dependencies.std]
features = {std_features:?}
path = {src_dir_std:?}
[dependencies.test]
path = {src_dir_test:?}
                "#,
                std_features = std_features,
                src_dir_std = src_dir.join("std"),
                src_dir_test = src_dir.join("test"),
            ),
        };
        let manifest = format!(
            r#"
[package]
authors = ["rustc-build-sysroot"]
name = "sysroot"
version = "0.0.0"

[lib]
# empty dummy, just so that things are being built
path = "lib.rs"

{crates}

[patch.crates-io.rustc-std-workspace-core]
path = {src_dir_workspace_core:?}
[patch.crates-io.rustc-std-workspace-alloc]
path = {src_dir_workspace_alloc:?}
[patch.crates-io.rustc-std-workspace-std]
path = {src_dir_workspace_std:?}
            "#,
            crates = crates,
            src_dir_workspace_core = src_dir.join("rustc-std-workspace-core"),
            src_dir_workspace_alloc = src_dir.join("rustc-std-workspace-alloc"),
            src_dir_workspace_std = src_dir.join("rustc-std-workspace-std"),
        );
        File::create(&manifest_file)
            .context("failed to create manifest file")?
            .write_all(manifest.as_bytes())
            .context("failed to write manifest file")?;
        let lib = match config {
            SysrootConfig::NoStd => r#"#![no_std]"#,
            SysrootConfig::WithStd { .. } => "",
        };
        File::create(&lib_file)
            .context("failed to create lib file")?
            .write_all(lib.as_bytes())
            .context("failed to write lib file")?;

        // Run cargo.
        let (mut cmd, mut flags) = cargo_cmd();
        cmd.arg(mode.as_str());
        cmd.arg("--release");
        cmd.arg("--manifest-path");
        cmd.arg(&manifest_file);
        cmd.arg("--target");
        cmd.arg(&self.target);
        // Set rustflags.
        flags.push("-Zforce-unstable-if-unmarked".into());
        cmd.env("CARGO_ENCODED_RUSTFLAGS", encode_rustflags(flags));
        // Make sure the results end up where we expect them.
        let build_target_dir = build_dir.path().join("target");
        cmd.env("CARGO_TARGET_DIR", &build_target_dir);
        // To avoid metadata conflicts, we need to inject some custom data into the crate hash.
        // bootstrap does the same at
        // <https://github.com/rust-lang/rust/blob/c8e12cc8bf0de646234524924f39c85d9f3c7c37/src/bootstrap/builder.rs#L1613>.
        cmd.env("__CARGO_DEFAULT_LIB_METADATA", "rustc-build-sysroot");

        if cmd
            .status()
            .unwrap_or_else(|_| panic!("failed to execute cargo for sysroot build"))
            .success()
            .not()
        {
            bail!("sysroot build failed");
        }

        // Copy the output to a staging dir (so that we can do the final installation atomically.)
        fs::create_dir_all(&self.sysroot_dir).context("failed to create sysroot dir")?; // TempDir expects the parent to already exist
        let staging_dir = TempDir::new_in(&self.sysroot_dir, "rustc-build-sysroot")
            .context("failed to create staging dir")?;
        let out_dir = build_target_dir
            .join(&self.target)
            .join("release")
            .join("deps");
        for entry in fs::read_dir(&out_dir).context("failed to read cargo out dir")? {
            let entry = entry.context("failed to read cargo out dir entry")?;
            assert!(
                entry.file_type().unwrap().is_file(),
                "cargo out dir must not contain directories"
            );
            let entry = entry.path();
            fs::copy(&entry, staging_dir.path().join(entry.file_name().unwrap()))
                .context("failed to copy cargo out file")?;
        }

        // Write the hash file (into the staging dir).
        File::create(staging_dir.path().join(HASH_FILE_NAME))
            .context("failed to create hash file")?
            .write_all(cur_hash.to_string().as_bytes())
            .context("failed to write hash file")?;

        // Atomic copy to final destination via rename.
        let target_lib_dir = self.target_dir().join("lib");
        if target_lib_dir.exists() {
            // Remove potentially outdated files.
            fs::remove_dir_all(&target_lib_dir).context("failed to clean sysroot target dir")?;
        }
        fs::create_dir_all(
            target_lib_dir
                .parent()
                .expect("target/lib dir must have a parent"),
        )
        .context("failed to create target directory")?;
        fs::rename(staging_dir.path(), target_lib_dir).context("failed installing sysroot")?;

        Ok(())
    }
}
