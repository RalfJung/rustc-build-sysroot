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
use toml::{Table, Value};
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
    pub fn rustflag(mut self, rustflag: impl Into<OsString>) -> Self {
        self.rustflags.push(rustflag.into());
        self
    }

    /// Appends the given flags.
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
            // As long as the sysroot has a ptch for compiler_builtins, we need to include it in the
            // NoStd variant explicitly.
            SysrootConfig::NoStd => format!(
                r#"
                [dependencies.core]
                path = {src_dir_core:?}
                [dependencies.alloc]
                path = {src_dir_alloc:?}
                [dependencies.compiler_builtins]
                path = {src_dir_builtins:?}
                features = ["rustc-dep-of-std", "mem"]
                "#,
                src_dir_core = src_dir.join("core"),
                src_dir_alloc = src_dir.join("alloc"),
                src_dir_builtins = src_dir.join("compiler-builtins").join("compiler-builtins"),
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
        let unneeded_patches = match &self.config {
            SysrootConfig::NoStd => &["rustc-std-workspace-alloc", "rustc-std-workspace-std"][..],
            SysrootConfig::WithStd { .. } => &[][..],
        };

        let mut patches = extract_patches(src_dir);
        for (repo, repo_patches) in &mut patches {
            let repo_patches = repo_patches
                .as_table_mut()
                .unwrap_or_else(|| panic!("source `{}` is not a table", repo));

            // Remove any patches that we don't need
            for krate in unneeded_patches {
                repo_patches.remove(*krate);
            }

            // Remap paths to be relative to the source directory.
            for (krate, patch) in repo_patches {
                if let Some(path) = patch.get_mut("path") {
                    let curr_path = path
                        .as_str()
                        .unwrap_or_else(|| panic!("`{}.path` is not a string", krate));

                    *path = Value::String(src_dir.join(curr_path).display().to_string());
                }
            }
        }

        let mut table: Table = toml::from_str(&format!(
            r#"
            [package]
            authors = ["rustc-build-sysroot"]
            name = "custom-local-sysroot"
            version = "0.0.0"
            edition = "2018"

            [lib]
            # empty dummy, just so that things are being built
            path = "lib.rs"

            [profile.{DEFAULT_SYSROOT_PROFILE}]
            # We inherit from the local release profile, but then overwrite some
            # settings to ensure we still get a working sysroot.
            inherits = "release"
            panic = 'unwind'

            {crates}
            "#
        ))
        .expect("failed to parse toml");

        table.insert("patch".to_owned(), patches.into());
        toml::to_string(&table).expect("failed to serialize to toml")
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

        // Create the *parent* directroy of what we are going to create, so that we can later move
        // into it.
        fs::create_dir_all(&sysroot_target_dir.parent().unwrap())
            .context("failed to create target directory")?;
        // Remove potentially outdated files. Do this via rename to make it atomic.
        // We do this *before* the step that takes all the time. That means if a bunch of
        // these builds happen concurrently, then almost certainly this cleanup will happen before
        // any of them is done, i.e., we only delete outdated files, not new files.
        // (The delete will happen automatically when `unstaging_dir` gets dropped.)
        let unstaging_dir =
            TempDir::new_in(&self.sysroot_dir).context("failed to create un-staging dir")?;
        let _ = fs::rename(&sysroot_target_dir, &unstaging_dir); // rename may fail if the dir does not exist yet

        // Prepare a workspace for cargo
        let build_dir = TempDir::new().context("failed to create tempdir")?;
        // Cargo.lock
        let lock_file = build_dir.path().join("Cargo.lock");
        let lock_file_src = {
            // Since <https://github.com/rust-lang/rust/pull/128534>, the lock file
            // lives inside the src_dir.
            let new_lock_file_name = src_dir.join("Cargo.lock");
            if new_lock_file_name.exists() {
                new_lock_file_name
            } else {
                // Previously, the lock file lived one folder up.
                src_dir
                    .parent()
                    .expect("src_dir must have a parent")
                    .join("Cargo.lock")
            }
        };
        fs::copy(lock_file_src, &lock_file)
            .context("failed to copy lockfile from sysroot source")?;
        make_writeable(&lock_file).context("failed to make lockfile writeable")?;
        // Cargo.toml
        let manifest_file = build_dir.path().join("Cargo.toml");
        let manifest = self.gen_manifest(src_dir);
        fs::write(&manifest_file, manifest.as_bytes()).context("failed to write manifest file")?;
        // lib.rs
        let lib_file = build_dir.path().join("lib.rs");
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
        // Cargo provides multiple ways to adjust this and we need to overwrite all of them.
        let build_target_dir = build_dir.path().join("target");
        cmd.env("CARGO_TARGET_DIR", &build_target_dir);
        cmd.env("CARGO_BUILD_BUILD_DIR", &build_target_dir);
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
        // installation atomically). By creating this directory inside `sysroot_dir`, we ensure that
        // it is on the same file system (so `fs::rename`) works. This also means that the mtime of
        // `sysroot_dir` gets updated, which rustc bootstrap relies on as a signal that a rebuild
        // happened.
        fs::create_dir_all(&self.sysroot_dir).context("failed to create sysroot dir")?; // TempDir expects the parent to already exist
        let staging_dir =
            TempDir::new_in(&self.sysroot_dir).context("failed to create staging dir")?;
        // Copy the output to `$staging/lib`.
        let staging_lib_dir = staging_dir.path().join("lib");
        fs::create_dir(&staging_lib_dir).context("failed to create staging/lib dir")?;
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

        // Write the hash file (into the staging dir).
        fs::write(
            staging_dir.path().join(HASH_FILE_NAME),
            cur_hash.to_string().as_bytes(),
        )
        .context("failed to write hash file")?;

        // Atomic copy to final destination via rename.
        // The rename can fail if there was a concurrent build.
        if fs::rename(staging_dir.path(), sysroot_target_dir).is_err() {
            // Ensure that that build is identical to what we were going to do.
            if self.sysroot_read_hash() != Some(cur_hash) {
                bail!("detected a concurrent sysroot build with different settings");
            }
        }

        Ok(SysrootStatus::SysrootBuilt)
    }
}

/// Collect the patches from the sysroot's workspace `Cargo.toml`.
fn extract_patches(src_dir: &Path) -> Table {
    // Assume no patch is needed if the workspace Cargo.toml doesn't exist
    let workspace_manifest = src_dir.join("Cargo.toml");
    let f = fs::read_to_string(&workspace_manifest).unwrap_or_else(|e| {
        panic!(
            "unable to read workspace manifest at `{}`: {}",
            workspace_manifest.display(),
            e
        )
    });
    let mut t: Table = toml::from_str(&f).expect("invalid sysroot workspace Cargo.toml");
    // We only care about the patch table.
    t.remove("patch")
        .map(|v| match v {
            Value::Table(map) => map,
            _ => panic!("`patch` is not a table"),
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a manifest for inspecting, returning the manifest and a source directory.
    fn setup_manifest_test(config: SysrootConfig) -> (Table, TempDir) {
        let workspace_toml = r#"
            [workspace]
            foo = "bar"

            [patch.crates-io]
            foo = { path = "bar" }
            rustc-std-workspace-core = { path = "core" }
            rustc-std-workspace-alloc = { path = "alloc" }
            rustc-std-workspace-std = { path = "std" }
        "#;

        let sysroot = tempfile::tempdir().unwrap(); // dummy sysroot dir, shouldn't be written
        let src_dir = tempfile::tempdir().unwrap();
        let f = src_dir.path().join("Cargo.toml");
        fs::write(&f, workspace_toml).unwrap();

        let builder = SysrootBuilder::new(sysroot.path(), "sometarget").sysroot_config(config);
        let manifest: Table = toml::from_str(&builder.gen_manifest(src_dir.path())).unwrap();
        (manifest, src_dir)
    }

    /// Check that a crate's patch is set to the given path, or that it doesn't exist if `None`.
    #[track_caller]
    fn check_patch_path(manifest: &Table, krate: &str, path: Option<&Path>) {
        let patches = &manifest["patch"]["crates-io"];
        match path {
            Some(path) => assert_eq!(
                &patches[krate]["path"].as_str().unwrap(),
                &path.to_str().unwrap()
            ),
            None => assert!(patches.get(krate).is_none()),
        }
    }

    #[test]
    fn check_patches_no_std() {
        let (manifest, src_dir) = setup_manifest_test(SysrootConfig::NoStd);

        // Ensure that we use the manifest's paths but mapped to the source directory
        check_patch_path(&manifest, "foo", Some(&src_dir.path().join("bar")));
        check_patch_path(
            &manifest,
            "rustc-std-workspace-core",
            Some(&src_dir.path().join("core")),
        );

        // For `NoStd`, we shouldn't get the alloc and std patches.
        check_patch_path(&manifest, "rustc-std-workspace-alloc", None);
        check_patch_path(&manifest, "rustc-std-workspace-std", None);
    }

    #[test]
    fn check_patches_with_std() {
        let (manifest, src_dir) = setup_manifest_test(SysrootConfig::WithStd {
            std_features: Vec::new(),
        });

        // For `WithStd`, we should get all patches.
        check_patch_path(&manifest, "foo", Some(&src_dir.path().join("bar")));
        check_patch_path(
            &manifest,
            "rustc-std-workspace-core",
            Some(&src_dir.path().join("core")),
        );
        check_patch_path(
            &manifest,
            "rustc-std-workspace-alloc",
            Some(&src_dir.path().join("alloc")),
        );
        check_patch_path(
            &manifest,
            "rustc-std-workspace-std",
            Some(&src_dir.path().join("std")),
        );
    }
}
