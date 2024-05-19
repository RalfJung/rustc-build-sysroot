//! Offers an easy way to build a rustc sysroot from source.
#![warn(missing_docs)]
// We prefer to always borrow rather than having to figure out whether we can move or borrow (which
// depends on whether the variable is used again later).
#![allow(clippy::needless_borrows_for_generic_args)]

use std::collections::hash_map::DefaultHasher;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use tempfile::TempDir;
use walkdir::WalkDir;

/// The name of the profile used for buliding the sysroot.
const DEFAULT_SYSROOT_PROFILE: &str = "custom_sysroot";

fn rustc_sysroot_dir(mut rustc: Command) -> Result<PathBuf> {
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
    let sysroot = PathBuf::from(sysroot.trim_end_matches('\n'));
    if !sysroot.is_dir() {
        bail!(
            "sysroot directory `{}` is not a directory",
            sysroot.display()
        );
    }
    Ok(sysroot)
}

/// Returns where the given rustc stores its sysroot source code.
pub fn rustc_sysroot_src(rustc: Command) -> Result<PathBuf> {
    let sysroot = rustc_sysroot_dir(rustc)?;
    let rustc_src = sysroot
        .join("lib")
        .join("rustlib")
        .join("src")
        .join("rust")
        .join("library");
    // There could be symlinks here, so better canonicalize to avoid busting the cache due to path
    // changes.
    let rustc_src = rustc_src.canonicalize().unwrap_or(rustc_src);
    Ok(rustc_src)
}

/// Encode a list of rustflags for use in CARGO_ENCODED_RUSTFLAGS.
pub fn encode_rustflags(flags: &[OsString]) -> OsString {
    let mut res = OsString::new();
    for flag in flags {
        if !res.is_empty() {
            res.push(OsStr::new("\x1f"));
        }
        // Cargo ignores this env var if it's not UTF-8.
        let flag = flag.to_str().expect("rustflags must be valid UTF-8");
        if flag.contains('\x1f') {
            panic!("rustflags must not contain `\\x1f` separator");
        }
        res.push(flag);
    }
    res
}

/// Make a file writeable.
#[cfg(unix)]
fn make_writeable(p: &Path) -> Result<()> {
    // On Unix we avoid `set_readonly(false)`, see
    // <https://rust-lang.github.io/rust-clippy/master/index.html#permissions_set_readonly_false>.
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    let perms = fs::metadata(p)?.permissions();
    let perms = Permissions::from_mode(perms.mode() | 0o600); // read/write for owner
    fs::set_permissions(p, perms).context("cannot set permissions")?;
    Ok(())
}

/// Make a file writeable.
#[cfg(not(unix))]
fn make_writeable(p: &Path) -> Result<()> {
    let mut perms = fs::metadata(p)?.permissions();
    perms.set_readonly(false);
    fs::set_permissions(p, perms).context("cannot set permissions")?;
    Ok(())
}

/// Determine the location of the sysroot that is distributed with rustc.
fn dist_sysroot() -> Result<PathBuf> {
    let cmd = env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
    rustc_sysroot_dir(Command::new(cmd))
}

#[cfg(unix)]
fn symlink_or_copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::os::unix::fs::symlink(src, dst)?;
    Ok(())
}

#[cfg(not(unix))]
fn symlink_or_copy_dir(src: &Path, dst: &Path) -> Result<()> {
    for e in WalkDir::new(src) {
        // This is only an error when there's some sort of intermittent IO error
        // during iteration.
        // see https://doc.rust-lang.org/std/fs/struct.ReadDir.html
        let e = e?;
        let metadata = e.metadata()?;

        let src_file = e.path();
        let relative_path = src_file.strip_prefix(src)?;
        let dst_file = dst.join(relative_path);

        if metadata.is_dir() {
            // ensure the destination directory exists
            fs::create_dir_all(&dst_file)?;
        } else {
            // copy the file
            fs::copy(&src_file, &dst_file)?;
        };
    }

    Ok(())
}

/// Hash the metadata and size of every file in a directory, recursively.
fn hash_recursive(path: &Path, hasher: &mut DefaultHasher) -> Result<()> {
    // We sort the entries to ensure a stable hash.
    for entry in WalkDir::new(path)
        .follow_links(true)
        .sort_by_file_name()
        .into_iter()
    {
        let entry = entry?;
        // WalkDir yields the directories as well, and File::open will succeed on them. The
        // reliable way to distinguish directories here is to check explicitly.
        if entry.file_type().is_dir() {
            continue;
        }
        let meta = entry.metadata()?;
        // Hashing the mtime and file size should catch basically all mutations,
        // and is faster than hashing the file contents.
        meta.modified()?.hash(hasher);
        meta.len().hash(hasher);
    }
    Ok(())
}

/// The build mode to use for this sysroot.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum BuildMode {
    /// Do a full sysroot build. Suited for all purposes (like the regular sysroot), but only works
    /// for the host or for targets that have suitable development tools installed.
    Build,
    /// Do a check-only sysroot build. This is only suited for check-only builds of crates, but on
    /// the plus side it works for *arbitrary* targets without having any special tools installed.
    Check,
}

impl BuildMode {
    /// Returns a string with the cargo command matching this build mode.
    pub fn as_str(&self) -> &str {
        use BuildMode::*;
        match self {
            Build => "build",
            Check => "check",
        }
    }
}

/// Settings controlling how the sysroot will be built.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SysrootConfig {
    /// Build a no-std (only core and alloc) sysroot.
    NoStd,
    /// Build a full sysroot with the `std` and `test` crates.
    WithStd {
        /// Features to enable for the `std` crate.
        std_features: Vec<String>,
    },
}

/// Information about a to-be-created sysroot.
pub struct SysrootBuilder<'a> {
    sysroot_dir: PathBuf,
    target: OsString,
    config: SysrootConfig,
    mode: BuildMode,
    rustflags: Vec<OsString>,
    cargo: Option<Command>,
    rustc_version: Option<rustc_version::VersionMeta>,
    when_build_required: Option<Box<dyn FnOnce() + 'a>>,
}

/// Whether a successful [`SysrootBuilder::build_from_source`] call found a cached sysroot or
/// built a fresh one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SysrootStatus {
    /// The required sysroot is already cached.
    AlreadyCached,
    /// A fresh sysroot was just compiled.
    SysrootBuilt,
}

/// Hash file name (in target/lib directory).
const HASH_FILE_NAME: &str = ".rustc-build-sysroot-hash";

impl<'a> SysrootBuilder<'a> {
    /// Prepare to create a new sysroot in the given folder (that folder should later be passed to
    /// rustc via `--sysroot`), for the given target.
    pub fn new(sysroot_dir: &Path, target: impl Into<OsString>) -> Self {
        let default_flags = &[
            // This is usually set by bootstrap via `RUSTC_FORCE_UNSTABLE`.
            "-Zforce-unstable-if-unmarked",
            // Don't fail when there are lints.
            // The whole point of this crate is to build the standard library in nonstandard
            // configurations, which may trip lints due to untested combinations of cfgs.
            // This matches what cargo does for dependencies.
            // We cannot set `--cap-lints=allow` because Cargo needs to parse warnings to understand the
            // output of --print=file-names for crate-types that the target does not support.
            "--cap-lints=warn",
            // We allow `unexpected_cfgs` as the sysroot has tons of custom `cfg` that rustc does not know about.
            "-Aunexpected_cfgs",
        ];
        SysrootBuilder {
            sysroot_dir: sysroot_dir.to_owned(),
            target: target.into(),
            config: SysrootConfig::WithStd {
                std_features: vec![],
            },
            mode: BuildMode::Build,
            rustflags: default_flags.iter().map(Into::into).collect(),
            cargo: None,
            rustc_version: None,
            when_build_required: None,
        }
    }

    /// Sets the build mode (regular build vs check-only build).
    pub fn build_mode(mut self, build_mode: BuildMode) -> Self {
        self.mode = build_mode;
        self
    }

    /// Sets the sysroot configuration (which parts of the sysroot to build and with which features).
    pub fn sysroot_config(mut self, sysroot_config: SysrootConfig) -> Self {
        self.config = sysroot_config;
        self
    }

    /// Appends the given flag.
    ///
    /// If no `--cap-lints` argument is configured, we will add `--cap-lints=warn`.
    /// This emulates the usual behavior of Cargo: Lints are normally capped when building
    /// dependencies, except that they are not capped when building path dependencies, except that
    /// path dependencies are still capped if they are part of `-Zbuild-std`.
    pub fn rustflag(mut self, rustflag: impl Into<OsString>) -> Self {
        self.rustflags.push(rustflag.into());
        self
    }

    /// Appends the given flags.
    ///
    /// If no `--cap-lints` argument is configured, we will add `--cap-lints=warn`. See
    /// [`SysrootBuilder::rustflag`] for more explanation.
    pub fn rustflags(mut self, rustflags: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        self.rustflags.extend(rustflags.into_iter().map(Into::into));
        self
    }

    /// Sets the cargo command to call.
    ///
    /// This will be invoked with `output()`, so if stdout/stderr should be inherited
    /// then that needs to be set explicitly.
    pub fn cargo(mut self, cargo: Command) -> Self {
        self.cargo = Some(cargo);
        self
    }

    /// Sets the rustc version information (in case the user has that available).
    pub fn rustc_version(mut self, rustc_version: rustc_version::VersionMeta) -> Self {
        self.rustc_version = Some(rustc_version);
        self
    }

    /// Sets the hook that will be called if we don't have a cached sysroot available and a new one
    /// will be compiled.
    pub fn when_build_required(mut self, when_build_required: impl FnOnce() + 'a) -> Self {
        self.when_build_required = Some(Box::new(when_build_required));
        self
    }

    /// Our configured target can be either a built-in target name, or a path to a target file.
    /// We use the same logic as rustc to tell which is which:
    /// https://github.com/rust-lang/rust/blob/8d39ec1825024f3014e1f847942ac5bbfcf055b0/compiler/rustc_session/src/config.rs#L2252-L2263
    fn target_name(&self) -> &OsStr {
        let path = Path::new(&self.target);
        if path.extension().and_then(OsStr::to_str) == Some("json") {
            // Path::file_stem and Path::extension are the last component of the path split on the
            // rightmost '.' so if we have an extension we must have a file_stem.
            path.file_stem().unwrap()
        } else {
            // The configured target doesn't end in ".json", so we assume that this is a builtin
            // target.
            &self.target
        }
    }

    fn sysroot_target_dir(&self) -> PathBuf {
        self.sysroot_dir
            .join("lib")
            .join("rustlib")
            .join(self.target_name())
    }

    /// Computes the hash for the sysroot, so that we know whether we have to rebuild.
    fn sysroot_compute_hash(
        &self,
        src_dir: &Path,
        rustc_version: &rustc_version::VersionMeta,
    ) -> Result<u64> {
        let mut hasher = DefaultHasher::new();

        src_dir.hash(&mut hasher);
        hash_recursive(src_dir, &mut hasher)?;
        self.config.hash(&mut hasher);
        self.mode.hash(&mut hasher);
        self.rustflags.hash(&mut hasher);
        rustc_version.hash(&mut hasher);

        Ok(hasher.finish())
    }

    fn sysroot_read_hash(&self) -> Option<u64> {
        let hash_file = self.sysroot_target_dir().join(HASH_FILE_NAME);
        let hash = fs::read_to_string(&hash_file).ok()?;
        hash.parse().ok()
    }

    /// Generate the contents of the manifest file for the sysroot build.
    fn gen_manifest(&self, src_dir: &Path) -> String {
        let have_sysroot_crate = src_dir.join("sysroot").exists();
        let crates = match &self.config {
            SysrootConfig::NoStd => format!(
                r#"
[dependencies.core]
path = {src_dir_core:?}
[dependencies.alloc]
path = {src_dir_alloc:?}
[dependencies.compiler_builtins]
features = ["rustc-dep-of-std", "mem"]
version = "*"
                "#,
                src_dir_core = src_dir.join("core"),
                src_dir_alloc = src_dir.join("alloc"),
            ),
            SysrootConfig::WithStd { std_features } if have_sysroot_crate => format!(
                r#"
[dependencies.std]
features = {std_features:?}
path = {src_dir_std:?}
[dependencies.sysroot]
path = {src_dir_sysroot:?}
                "#,
                std_features = std_features,
                src_dir_std = src_dir.join("std"),
                src_dir_sysroot = src_dir.join("sysroot"),
            ),
            // Fallback for old rustc where the main crate was `test`, not `sysroot`
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

        // If we include a patch for rustc-std-workspace-std for no_std sysroot builds, we get a
        // warning from Cargo that the patch is unused. If this patching ever breaks that lint will
        // probably be very helpful, so it would be best to not disable it.
        // Currently the only user of rustc-std-workspace-alloc is std_detect, which is only used
        // by std. So we only need to patch rustc-std-workspace-core in no_std sysroot builds, or
        // that patch also produces a warning.
        let patches = match &self.config {
            SysrootConfig::NoStd => format!(
                r#"
[patch.crates-io.rustc-std-workspace-core]
path = {src_dir_workspace_core:?}
                "#,
                src_dir_workspace_core = src_dir.join("rustc-std-workspace-core"),
            ),
            SysrootConfig::WithStd { .. } => format!(
                r#"
[patch.crates-io.rustc-std-workspace-core]
path = {src_dir_workspace_core:?}
[patch.crates-io.rustc-std-workspace-alloc]
path = {src_dir_workspace_alloc:?}
[patch.crates-io.rustc-std-workspace-std]
path = {src_dir_workspace_std:?}
                "#,
                src_dir_workspace_core = src_dir.join("rustc-std-workspace-core"),
                src_dir_workspace_alloc = src_dir.join("rustc-std-workspace-alloc"),
                src_dir_workspace_std = src_dir.join("rustc-std-workspace-std"),
            ),
        };

        format!(
            r#"
[package]
authors = ["rustc-build-sysroot"]
name = "custom-local-sysroot"
version = "0.0.0"

[lib]
# empty dummy, just so that things are being built
path = "lib.rs"

[profile.{DEFAULT_SYSROOT_PROFILE}]
# We inherit from the local release profile, but then overwrite some
# settings to ensure we still get a working sysroot.
inherits = "release"
panic = 'unwind'

{crates}

{patches}
            "#
        )
    }

    /// Build the `self` sysroot from the given sources.
    ///
    /// `src_dir` must be the `library` source folder, i.e., the one that contains `std/Cargo.toml`.
    pub fn build_from_source(mut self, src_dir: &Path) -> Result<SysrootStatus> {
        // A bit of preparation.
        if !src_dir.join("std").join("Cargo.toml").exists() {
            bail!(
                "{:?} does not seem to be a rust library source folder: `src/Cargo.toml` not found",
                src_dir
            );
        }
        let sysroot_target_dir = self.sysroot_target_dir();
        let target_name = self.target_name().to_owned();
        let cargo = self.cargo.take().unwrap_or_else(|| {
            Command::new(env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo")))
        });
        let rustc_version = match self.rustc_version.take() {
            Some(v) => v,
            None => rustc_version::version_meta()?,
        };

        // Check if we even need to do anything.
        let cur_hash = self.sysroot_compute_hash(src_dir, &rustc_version)?;
        if self.sysroot_read_hash() == Some(cur_hash) {
            // Already done!
            return Ok(SysrootStatus::AlreadyCached);
        }

        // A build is required, so we run the when-build-required function if one was set.
        if let Some(when_build_required) = self.when_build_required.take() {
            when_build_required();
        }

        // Prepare a workspace for cargo
        let build_dir = TempDir::new().context("failed to create tempdir")?;
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
        make_writeable(&lock_file).context("failed to make lockfile writeable")?;
        let manifest = self.gen_manifest(src_dir);
        fs::write(&manifest_file, manifest.as_bytes()).context("failed to write manifest file")?;
        let lib = match self.config {
            SysrootConfig::NoStd => r#"#![no_std]"#,
            SysrootConfig::WithStd { .. } => "",
        };
        fs::write(&lib_file, lib.as_bytes()).context("failed to write lib file")?;

        // Run cargo.
        let mut cmd = cargo;
        cmd.arg(self.mode.as_str());
        cmd.arg("--profile");
        cmd.arg(DEFAULT_SYSROOT_PROFILE);
        cmd.arg("--manifest-path");
        cmd.arg(&manifest_file);
        cmd.arg("--target");
        cmd.arg(&self.target);
        // Set rustflags.
        cmd.env("CARGO_ENCODED_RUSTFLAGS", encode_rustflags(&self.rustflags));
        // Make sure the results end up where we expect them.
        let build_target_dir = build_dir.path().join("target");
        cmd.env("CARGO_TARGET_DIR", &build_target_dir);
        // To avoid metadata conflicts, we need to inject some custom data into the crate hash.
        // bootstrap does the same at
        // <https://github.com/rust-lang/rust/blob/c8e12cc8bf0de646234524924f39c85d9f3c7c37/src/bootstrap/builder.rs#L1613>.
        cmd.env("__CARGO_DEFAULT_LIB_METADATA", "rustc-build-sysroot");

        let output = cmd
            .output()
            .context("failed to execute cargo for sysroot build")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.is_empty() {
                bail!("sysroot build failed");
            } else {
                bail!("sysroot build failed; stderr:\n{}", stderr);
            }
        }

        // Create a staging dir that will become the target sysroot dir (so that we can do the final
        // installation atomically).
        fs::create_dir_all(&self.sysroot_dir).context("failed to create sysroot dir")?; // TempDir expects the parent to already exist
        let staging_dir =
            TempDir::new_in(&self.sysroot_dir).context("failed to create staging dir")?;
        // Copy the output to `$staging/lib`.
        let staging_lib_dir = staging_dir.path().join("lib");
        fs::create_dir(&staging_lib_dir).context("faiked to create staging/lib dir")?;
        let out_dir = build_target_dir
            .join(&target_name)
            .join(DEFAULT_SYSROOT_PROFILE)
            .join("deps");
        for entry in fs::read_dir(&out_dir).context("failed to read cargo out dir")? {
            let entry = entry.context("failed to read cargo out dir entry")?;
            assert!(
                entry.file_type().unwrap().is_file(),
                "cargo out dir must not contain directories"
            );
            let entry = entry.path();
            fs::copy(&entry, staging_lib_dir.join(entry.file_name().unwrap()))
                .context("failed to copy cargo out file")?;
        }
        // If we are doing a full build, copy any other files and directories that need copying from
        // the original sysroot.
        if matches!(self.mode, BuildMode::Build) {
            let extra_copy_paths = &["bin"];
            let dist_sysroot_target_dir = dist_sysroot()?
                .join("lib")
                .join("rustlib")
                .join(&target_name);
            for path in extra_copy_paths {
                let src = dist_sysroot_target_dir.join(path);
                if src.exists() {
                    let dst = staging_dir.path().join(path);
                    symlink_or_copy_dir(&src, &dst).with_context(|| {
                        format!(
                            "failed to symlink/copy `{src}` to `{dst}`",
                            src = src.display(),
                            dst = dst.display(),
                        )
                    })?;
                }
            }
        }

        // Write the hash file (into the staging dir).
        fs::write(
            staging_dir.path().join(HASH_FILE_NAME),
            cur_hash.to_string().as_bytes(),
        )
        .context("failed to write hash file")?;

        // Atomic copy to final destination via rename.
        if sysroot_target_dir.exists() {
            // Remove potentially outdated files.
            fs::remove_dir_all(&sysroot_target_dir)
                .context("failed to clean sysroot target dir")?;
        }
        // Create the *parent* directroy so we can move into it.
        fs::create_dir_all(&sysroot_target_dir.parent().unwrap())
            .context("failed to create target directory")?;
        fs::rename(staging_dir.path(), sysroot_target_dir).context("failed installing sysroot")?;

        Ok(SysrootStatus::SysrootBuilt)
    }
}
