#![cfg_attr(not(test), deny(clippy::unwrap_used))]
use camino::{Utf8Path, Utf8PathBuf};
use clap::{ArgAction, Parser, Subcommand};
use eyre::bail;
use eyre::{ensure, eyre, WrapErr};
use internal_store::StoredDistribution;
use itertools::Itertools;
use prelude::*;
use std::path::Path as StdPath;

mod internal_store;
pub(crate) mod prelude;
mod python;
pub(crate) mod venv;

use venv::{Virtpy, VirtpyPaths};

#[cfg(unix)]
pub(crate) use fs_err::os::unix::fs::symlink as symlink_dir;
#[cfg(windows)]
pub(crate) use fs_err::os::windows::fs::symlink_dir;

#[cfg(unix)]
pub(crate) use fs_err::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
pub(crate) use fs_err::os::windows::fs::symlink_file;

type Path = Utf8Path;
type PathBuf = Utf8PathBuf;

#[derive(Parser)]
#[command(version)]
/// Create slim venvs for Python using shared, symlinked dependencies.
struct Opt {
    #[command(subcommand)] // Note that we mark a field as a subcommand
    cmd: Command,
    /// Increase verbosity of output.
    #[arg(short, action = ArgAction::Count, global = true)]
    verbose: u8,
    #[arg(long, hide = true)]
    project_dir: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new virtpy environment
    New {
        path: Option<PathBuf>,
        /// The python to use. Either a path or an indicator of the form `python3.7` or `3.7`
        #[arg(short, long, default_value = "3")]
        python: String,
        #[arg(long)]
        without_pip_shim: bool,
        /// Don't add pkg_resources module that is usually installed into venvs alongside setuptools.
        #[arg(long)]
        without_package_resources: bool,
        #[command(flatten)]
        check_strategy: CheckStrategy,
    },
    /// Add package to virtpy from wheel file
    Add {
        file: PathBuf,
        #[arg(long)]
        virtpy_path: Option<PathBuf>,
        #[command(flatten)]
        check_strategy: CheckStrategy,
    },
    /// Remove package from virtpy
    Remove {
        distributions: Vec<String>,
        #[arg(long)]
        virtpy_path: Option<PathBuf>,
    },
    /// Install executable package into an isolated virtpy
    Install {
        package: Vec<String>,
        /// Reinstall, if it already exists
        #[arg(short, long)]
        force: bool,
        #[arg(long)]
        allow_prereleases: bool,
        /// The python to use. Either a path or an indicator of the form `python3.7` or `3.7`
        #[arg(short, long, default_value = "3")]
        python: String,
        #[command(flatten)]
        check_strategy: CheckStrategy,
    },
    /// Delete the virtpy of a previously installed executable package
    Uninstall { package: Vec<String> },
    /// Print paths where various files are stored
    #[command(subcommand)]
    Path(PathCmd),
    /// Get info about or modify the internal package store
    #[command(subcommand)]
    InternalStore(InternalStoreCmd),
    /// Helper commands for internal use, e.g. by the pip shim.
    #[command(subcommand)]
    InternalUseOnly(InternalUseOnly),
    /// List paths of all virtpys
    ListAll,
}

#[allow(unused)]
#[derive(PartialEq, Eq)]
pub(crate) enum Platform {
    Unix,
    Windows,
}

pub(crate) fn platform() -> Platform {
    #[cfg(unix)]
    {
        Platform::Unix
    }
    #[cfg(windows)]
    {
        Platform::Windows
    }
}

#[derive(Subcommand)]
enum InternalStoreCmd {
    /// Find virtpys that have been moved or deleted and unneeded files in the central store.
    Gc {
        /// Delete unnecessary files
        #[arg(long)]
        remove: bool,
    },
    /// Show how much storage is used
    Stats {
        /// Show sizes in bytes
        #[arg(long, short)]
        bytes: bool,
        /// Use binary prefixes instead of SI.
        ///
        /// This uses powers of 1024 instead of 1000 and will print the accompanying symbol (e.g. 1 KiB for 1024 bytes).
        /// Has no effect if `--bytes` is passed.
        #[arg(long)]
        binary_prefix: bool,
    },
    /// Check integrity of the files of all python modules in the internal store.
    ///
    /// If someone edited a file in any virtpy, those changes are visible in every virtpy
    /// using that file. This command detects if any changes were made to any file
    /// in the internal store.
    // FIXME: Currently, we're not verifying the file hashes on installation, so
    // if a module's RECORD is faulty, those files will also appear here
    Verify,
}

#[derive(Subcommand)]
enum InternalUseOnly {
    /// Install the wheel file into the given virtpy
    AddFromFile {
        virtpy: PathBuf,
        file: PathBuf,
        #[command(flatten)]
        check_strategy: CheckStrategy,
        #[arg(long)]
        use_pep517: bool,
    },
    /// Return path to globally available python executable of the same version as used in virtpy
    ///
    /// On systems where the venv executable is symlinked, it will return the linked one.
    /// Otherwise, it will search for the executable by version which might return a different one.
    GlobalPython { virtpy: PathBuf },
    /// List packages in same format as pip list
    ListPackages { virtpy: PathBuf },
}

#[derive(Subcommand)]
enum PathCmd {
    /// Directory where executables are placed by `virtpy install`
    Bin,
    /// Alias for `bin`
    Executables,
    /// Directory where virtpy stores all its data
    Storage,
}

const DEFAULT_VIRTPY_PATH: &str = ".venv";
const INSTALLED_DISTRIBUTIONS: &str = "installed_distributions.json";
const CENTRAL_METADATA: &str = "virtpy_central_metadata";
const LINK_METADATA: &str = "virtpy_link_metadata";
const LINK_LOCATION: &str = "link_location";
const CENTRAL_LOCATION: &str = "central_location";

// name of file we add to .dist-info dir containing the distribution's hash
const DIST_HASH_FILE: &str = "DISTRIBUTION_HASH";
const INSTALLER_FILE: &str = "INSTALLER";

fn check_output(cmd: &mut std::process::Command) -> Result<String> {
    String::from_utf8(_check_output(cmd)?)
        .wrap_err_with(|| eyre!("output isn't valid utf8 for {cmd:?}"))
}

fn check_status(cmd: &mut std::process::Command) -> Result<()> {
    _check_output(cmd).map(drop)
}

fn _check_output(cmd: &mut std::process::Command) -> Result<Vec<u8>> {
    let output = cmd.output()?;
    ensure!(output.status.success(), {
        let error = String::from_utf8_lossy(&output.stderr);
        eyre!("command failed\n    {cmd:?}:\n{error}")
    });
    Ok(output.stdout)
}

// Context pattern
struct Ctx {
    proj_dirs: ProjectDirs,
    options: Options,
}

// toplevel options
#[derive(Copy, Clone)]
pub(crate) struct Options {
    verbose: u8,
}

#[derive(clap::Args)]
struct CheckStrategy {
    /// How to check integrity of wheel packages.
    ///
    /// The official specification requires to fail when installing packages where the
    /// metadata doesn't match its contents. However, pip doesn't conform with this
    /// so you may encounter invalid packages that won't be fixed.
    /// With the "repair" strategy, the wheel's contents are considered correct and the
    /// metadata is changed to match.
    #[arg(value_enum, long, default_value = "repair")]
    check_strategy: python::wheel::CheckStrategy,
}

/// The directory where the internal store is placed.
/// We default to the data directory that the [`directories`] crate gives us,
/// but it can also be overridden via cli argument. This exists primarily for testability.
/// Different project directories can exist simultaneously, but all virtpy calls
/// affecting a venv have to know what internal store the venv is linked with.
pub(crate) struct ProjectDirs {
    data_dir: PathBuf,
}

impl ProjectDirs {
    fn new() -> Option<Self> {
        directories::ProjectDirs::from("", "", "virtpy").map(|proj_dirs| Self {
            data_dir: proj_dirs.data_dir().to_owned().into_utf8_pathbuf(),
        })
    }

    fn from_path(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn create_dirs(&self) -> std::io::Result<()> {
        fs_err::create_dir_all(self.data())?;
        for path in self._required_paths() {
            fs_err::create_dir(path).or_else(ignore_target_exists)?;
        }
        Ok(())
    }

    fn _required_paths(&self) -> impl IntoIterator<Item = PathBuf> {
        [
            self.installations(),
            self.package_files(),
            self.executables(),
            self.virtpys(),
            self.tmp(),
            self.records(),
        ]
    }

    fn data(&self) -> &Path {
        &self.data_dir
    }

    fn installations(&self) -> PathBuf {
        self.data().join("installations")
    }

    fn virtpys(&self) -> PathBuf {
        self.data().join("virtpys")
    }

    // This is set to replace dist_infos().
    // Only the RECORD file from the wheel and the RECORD file we generated
    // for the wheel's data directory should be contained.
    fn records(&self) -> PathBuf {
        self.data().join("distribution_records")
    }

    fn package_files(&self) -> PathBuf {
        self.data().join("package_files")
    }

    fn package_file(&self, hash: &python::FileHash) -> PathBuf {
        self.package_files().join(&hash.0)
    }

    fn executables(&self) -> PathBuf {
        self.data().join("bin")
    }

    #[cfg(test)]
    fn executables_list(&self) -> Vec<String> {
        self.executables()
            .read_dir()
            .unwrap()
            .map(|entry| entry.unwrap())
            .map(|entry| entry.file_name().to_str().unwrap().to_owned())
            .collect()
    }

    fn installed_distributions_log(&self) -> PathBuf {
        self.data().join(INSTALLED_DISTRIBUTIONS)
    }

    fn package_folder(&self, package: &str) -> PathBuf {
        self.installations().join(format!("{package}.virtpy"))
    }

    fn installed_distributions(&self) -> Result<Vec<StoredDistribution>> {
        self.records()
            .read_dir()?
            .map(|dist_info_entry| {
                Ok(StoredDistribution {
                    distribution: python::Distribution::from_store_name(
                        dist_info_entry?
                            .path()
                            .file_name()
                            .expect("record file must have file name")
                            .to_str()
                            .expect("record path must be utf8"),
                    ),
                })
            })
            .collect()
    }

    // Using a directory in our data directory for temporary files ensures
    // that we can always just move them into their final location.
    // However, we'll need to manually clean up any old files.
    // TODO: add cleanup of old files
    fn tmp(&self) -> PathBuf {
        self.data().join("tmp")
    }
}

fn package_info_from_dist_info_dirname(dirname: &str) -> (&str, &str) {
    // NOTE: an old version allowed - in the distribution name.
    //       Was this a bug or deliberate because of a misconfigured package out there?
    //       I can't remember.
    let (_, distrib_name, version) = lazy_regex::regex_captures!(
        r"^([a-zA-Z_\.][a-zA-Z0-9_\.]*)-(\d*!.*|\d*\..*)\.dist-info$",
        dirname
    )
    .unwrap();
    (distrib_name, version)
}

fn path_to_virtpy(path_override: &Option<PathBuf>) -> &Path {
    path_override
        .as_deref()
        .unwrap_or_else(|| DEFAULT_VIRTPY_PATH.as_ref())
}

fn shim_info(ctx: &Ctx) -> Result<ShimInfo> {
    Ok(ShimInfo {
        proj_dirs: &ctx.proj_dirs,
        virtpy_exe: PathBuf::try_from(
            std::env::current_exe().wrap_err("failed to find the running executable's path")?,
        )?,
    })
}

// when we're calling out to python or poetry, we don't want to accidentally
// end up being influenced by whether or not a venv is active.
// Any call to a venv-binary must be explicitly made.
//
// Unfortunately, the activation script hides some of the information
// needed to fully undo the process. The variables storing the old state of
// PATH and PYTHONHOME are not being stored
fn deactivate_venv() {
    use std::env::{remove_var, set_var};

    // This should restore the PATH to the one set before activating the venv,
    // but it won't restore the PYTHONHOME, if there was one.
    // It could possibly be restored from the venv/pyvenv.cfg file. The "home"
    // key contains a path. However, there is no way to distinguish the default
    // home where no PYTHONHOME variable would be set from a different one
    // where it would be without also adding system-dependent knowledge
    // on what the default home is.
    match python::detection::venvless_path() {
        Err(e) => eprintln!("failed to remove venv from PATH: {e}"),
        Ok(Some(path)) => set_var("PATH", path),
        _ => {}
    }

    remove_var("VIRTUAL_ENV");
}

fn main() -> Result<()> {
    deactivate_venv();
    color_eyre::install()?;

    let opt = Opt::parse();
    let options = Options {
        verbose: opt.verbose,
    };

    // There's currently a bug with zip archive extraction on Windows where it will fail if the
    // destination uses extended length syntax. canonicalize() will always return such paths.
    // As a workaround, we use current_dir().join(dir) to get the absolute path.
    let current_dir =
        PathBuf::try_from(std::env::current_dir().wrap_err("can't get current dir")?)?;
    let proj_dirs = match opt.project_dir {
        Some(dir) => ProjectDirs::from_path(current_dir.join(dir)),
        None => ProjectDirs::new().ok_or_else(|| eyre!("failed to get proj dirs"))?,
    };
    proj_dirs.create_dirs()?;

    let ctx = Ctx { proj_dirs, options };

    match opt.cmd {
        Command::Add {
            file,
            virtpy_path,
            check_strategy: CheckStrategy { check_strategy },
        } => {
            let virtpy = virtpy_path.unwrap_or_else(|| PathBuf::from(DEFAULT_VIRTPY_PATH));
            add_from_file(&ctx, virtpy, file, check_strategy, false)?;
        }
        Command::Remove {
            distributions,
            virtpy_path,
        } => {
            Virtpy::from_existing(path_to_virtpy(&virtpy_path))?
                .remove_dependencies(distributions.into_iter().collect())?;
        }
        Command::New {
            path,
            python,
            without_pip_shim,
            without_package_resources,
            check_strategy: CheckStrategy { check_strategy },
        } => {
            let path = path.unwrap_or_else(|| PathBuf::from(DEFAULT_VIRTPY_PATH));

            let shim_info = (!without_pip_shim).then(|| shim_info(&ctx)).transpose()?;
            python::detection::detect(&python)
                .and_then(|python_path| {
                    Virtpy::create(
                        &ctx,
                        &python_path,
                        &path,
                        None,
                        shim_info,
                        !without_package_resources,
                        check_strategy,
                    )
                })
                .wrap_err("failed to create virtpy")?;
        }
        Command::Install {
            package,
            force,
            allow_prereleases,
            python,
            check_strategy: CheckStrategy { check_strategy },
        } => {
            let mut any_errors = false;
            for package in package {
                println!("installing {package}...");
                match install_executable_package(
                    &ctx,
                    &package,
                    force,
                    allow_prereleases,
                    &python,
                    check_strategy,
                ) {
                    Ok(InstalledStatus::NewlyInstalled) => println!("installed {package}."),
                    Ok(InstalledStatus::AlreadyInstalled) => {
                        println!("package is already installed.")
                    }
                    Err(err) => {
                        any_errors = true;
                        eprintln!("{err:?}");
                    }
                }
            }

            ensure!(!any_errors, "some installs failed");
        }
        Command::Uninstall { package } => {
            let mut any_errors = false;
            for package in package {
                match delete_executable_virtpy(&ctx, &package)
                    .wrap_err(eyre!("failed to uninstall {package}"))
                {
                    Ok(()) => println!("uninstalled {package}."),
                    Err(err) => {
                        any_errors = true;
                        eprintln!("{err:?}")
                    }
                }
            }
            if any_errors {
                bail!("some uninstalls failed");
            }
        }
        Command::InternalStore(InternalStoreCmd::Gc { remove }) => {
            internal_store::collect_garbage(&ctx, remove)?;
        }
        Command::Path(PathCmd::Bin) | Command::Path(PathCmd::Executables) => {
            println!("{}", ctx.proj_dirs.executables());
        }
        Command::Path(PathCmd::Storage) => {
            println!("{}", ctx.proj_dirs.data());
        }
        Command::InternalStore(InternalStoreCmd::Stats {
            bytes,
            binary_prefix,
        }) => {
            let human_readable = !bytes;
            internal_store::print_stats(&ctx, human_readable, binary_prefix)?;
        }
        Command::InternalStore(InternalStoreCmd::Verify) => {
            internal_store::print_verify_store(&ctx)?;
        }
        Command::InternalUseOnly(InternalUseOnly::AddFromFile {
            virtpy,
            file,
            check_strategy: CheckStrategy { check_strategy },
            use_pep517,
        }) => {
            add_from_file(&ctx, virtpy, file, check_strategy, use_pep517)?;
        }
        Command::InternalUseOnly(InternalUseOnly::GlobalPython { virtpy }) => {
            println!("{}", Virtpy::from_existing(&virtpy)?.global_python()?);
        }
        Command::InternalUseOnly(InternalUseOnly::ListPackages { virtpy }) => {
            let packages = Virtpy::from_existing(&virtpy)?.installed_distributions_metadata()?;
            let (successes, _failures): (Vec<_>, Vec<_>) = packages.into_iter().partition_result();

            // Print table of package name and version.
            // The columns are aligned at the width of the widest name and version.
            // Example:
            //
            // Package                Version
            // ---------------------- ------------------------------------
            // flatbuffers            1.12.1-git20200711.33e2d80-dfsg1-0.6
            // ubuntu-advantage-tools 8001
            // ujson                  5.1.0
            //
            let max_name_width = successes
                .iter()
                .map(|metadata| metadata.name.len())
                .max()
                .unwrap_or("Package".len());
            let max_version_width = successes
                .iter()
                .map(|metadata| metadata.version.len())
                .max()
                .unwrap_or("Version".len());

            println!(
                "{:p_width$} {:v_width$}",
                "Package",
                "Version",
                p_width = max_name_width,
                v_width = max_version_width
            );
            println!(
                // print "---" lines by printing
                // empty strings and filling with '-' up to specified width
                "{:-<p_width$} {:-<v_width$}",
                "",
                "",
                p_width = max_name_width,
                v_width = max_version_width
            );
            for p in successes {
                println!(
                    "{:p_width$} {:v_width$}",
                    p.name,
                    p.version,
                    p_width = max_name_width,
                    v_width = max_version_width
                );
            }
            // TODO: report errors
        }
        Command::ListAll => {
            // TODO: error handling
            let link_locations = ctx
                .proj_dirs
                .virtpys()
                .read_dir()?
                .map(|entry| entry.expect("virtpy dir should be readable"))
                .filter(|entry| entry.path().join(CENTRAL_METADATA).exists())
                .map(|entry| entry.path().join(CENTRAL_METADATA).join(LINK_LOCATION))
                // CHECKME: Is this guaranteed by construction
                .map(|path| fs_err::read_to_string(path).expect("link location should exist"))
                .sorted()
                .collect_vec();
            for path in link_locations {
                println!("{path}");
            }
        }
    }

    Ok(())
}

fn add_from_file(
    ctx: &Ctx,
    virtpy: PathBuf,
    file: PathBuf,
    check_strategy: python::wheel::CheckStrategy,
    use_pep517: bool,
) -> Result<()> {
    Virtpy::from_existing(&virtpy)?.add_dependency_from_file(ctx, &file, check_strategy, use_pep517)
}

enum InstalledStatus {
    NewlyInstalled,
    AlreadyInstalled,
}

fn install_executable_package(
    ctx: &Ctx,
    package: &str,
    force: bool,
    allow_prereleases: bool,
    python: &str,
    check_strategy: python::wheel::CheckStrategy,
) -> Result<InstalledStatus> {
    let package_folder = ctx.proj_dirs.package_folder(package);

    let python_path = python::detection::detect(python)?;

    if package_folder.exists() {
        if force {
            delete_executable_virtpy(ctx, package)?;
        } else {
            return Ok(InstalledStatus::AlreadyInstalled);
        }
    }

    check_poetry_available()?;

    let tmp_dir = tempdir::TempDir::new_in(ctx.proj_dirs.tmp(), &format!("install_{package}"))?;
    let tmp_path = tmp_dir.utf8_path().join(".venv");

    let virtpy = Virtpy::create(
        ctx,
        &python_path,
        &package_folder,
        None,
        Some(shim_info(ctx)?),
        true,
        check_strategy,
    )?;

    // if anything goes wrong, try to delete the incomplete installation
    let virtpy = scopeguard::guard(virtpy, |virtpy| {
        let _ = virtpy.delete();
    });

    symlink_dir(package_folder, tmp_path)?;

    init_temporary_poetry_project(tmp_dir.path())?;

    let mut cmd = std::process::Command::new("poetry");
    cmd.arg("add").arg(package).current_dir(tmp_dir.path());
    cmd.arg("--no-ansi");
    cmd.arg("--no-interaction");
    if allow_prereleases {
        cmd.arg("--allow-prereleases");
    }
    match ctx.options.verbose {
        // poetry uses -v for normal output
        // -vv for verbose
        // -vvv for debug
        0 => (),
        1 => {
            cmd.arg("-vv");
        }
        _ => {
            cmd.arg("-vvv");
        }
    };
    check_status(&mut cmd)
        .wrap_err("failed to install package into virtpy")
        .wrap_err_with(|| match virtpy.pip_shim_log() {
            Ok(log) => eyre!("{}", log.as_deref().unwrap_or("no log found")),
            Err(err) => eyre!("failed to read pip_shim_log: {err}"),
        })?;

    // {
    //     // allows manually introspecting the temporary files via breakpoint
    //     // or via exit
    //     println!("virtpy path: {}", virtpy.location());
    //     std::process::exit(1);
    // }

    let distrib = virtpy
        .dist_info(package)
        .and_then(internal_store::stored_distribution_of_installed_dist)?;

    let executables = distrib.executable_names(ctx)?;
    let exe_dir = virtpy.executables();
    let target_dir = ctx.proj_dirs.executables();
    for mut exe in executables {
        match crate::platform() {
            Platform::Unix => {}
            Platform::Windows => exe.push_str(".exe"),
        }
        symlink_file(exe_dir.join(&exe), target_dir.join(&exe))?;
    }

    // if everything succeeds, keep the venv
    std::mem::forget(virtpy);
    Ok(InstalledStatus::NewlyInstalled)
}

fn is_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

fn delete_executable_virtpy(ctx: &Ctx, package: &str) -> Result<()> {
    let virtpy_path = ctx.proj_dirs.package_folder(package);
    let virtpy = Virtpy::from_existing(&virtpy_path)?;
    virtpy.delete()?;

    // delete_global_package_executables
    // Executables in the binary directory are just symlinks.
    // The virtpy deletion has broken some of them, just need to find and delete them.
    for entry in ctx.proj_dirs.executables().read_dir()? {
        let entry = entry?;
        let target = fs_err::read_link(entry.path())?;
        if !target
            .try_exists()
            .wrap_err_with(|| eyre!("couldn't access {target:?}"))?
        {
            fs_err::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn delete_virtpy_backing(backing_folder: &Path) -> std::io::Result<()> {
    assert!(backing_folder.join(CENTRAL_METADATA).exists());
    fs_err::remove_dir_all(backing_folder)
}

/// The pip shim we are installing into a virtpy needs to know where the internal store
/// to which the venv is linked to is located.
/// For our integration tests, it's also important that the pip shim is calling the
/// freshly compiled virtpy executable and not the globally installed one.
pub(crate) struct ShimInfo<'a> {
    proj_dirs: &'a ProjectDirs,
    // TODO: make this part optional
    //       Having a backreference to the virtpy that created the venv is necessary
    //       for the unit tests to stay isolated, but it also means
    //       that you can't take the virtpy executable in a regular installation
    //       and move it to a different location without all venvs it created breaking.
    //       Regular venvs should try to find virtpy on the PATH.
    virtpy_exe: PathBuf,
}

fn check_poetry_available() -> Result<()> {
    pathsearch::find_executable_in_path("poetry")
        .map(drop)
        .ok_or_else(|| eyre!("this command requires poetry to be installed and on the PATH. (https://github.com/python-poetry/poetry)"))
}

fn init_temporary_poetry_project(path: &StdPath) -> Result<()> {
    check_status(
        std::process::Command::new("poetry")
            .current_dir(path)
            .args(["init", "-n"])
            .stdout(std::process::Stdio::null()),
    )
    .and_then(|_|
        // By default, poetry creates venvs in a global directory.
        // We need it to use our venvs.
        // Could also be done with `poetry config virtualenvs.create false --local`
        // but that's much slower, because poetry is a typical python project
        // that imports EVERYTHING at startup.
        fs_err::write(path.join("poetry.toml"), "[virtualenvs]\nin-project = true")
        .wrap_err("failed to activate in-project venv creation for tmp poetry project"))
    .wrap_err("failed to init poetry project")
}

fn executables_path(virtpy: &Path) -> PathBuf {
    virtpy.join(match cfg!(target_os = "windows") {
        true => "Scripts",
        false => "bin",
    })
}

fn python_path(virtpy: &Path) -> PathBuf {
    executables_path(virtpy).join("python")
}

fn dist_info_matches_package(dist_info: &Path, package: &str) -> bool {
    let entry_name = dist_info.file_name().expect("should be a dir path");
    let (distrib_name, _version) = package_info_from_dist_info_dirname(entry_name);
    distrib_name == package
}

// Returns a relative path that can be joined onto `base` to get `path`.
// `base` and `path` must be both be absolute or both relative.
// May not return a valid result, if `base` contains symlinks.
fn relative_path(base: impl AsRef<Path>, path: impl AsRef<Path>) -> Result<PathBuf> {
    _relative_path(base.as_ref(), path.as_ref())
}

fn _relative_path(base: &Path, path: &Path) -> Result<PathBuf> {
    ensure!(
        base.is_absolute() && path.is_absolute() || base.is_relative() && path.is_relative(),
        "paths need to be both relative or both absolute: {base:?}, {path:?}",
    );
    // can't assert this, because it requires IO and this function should be pure. But it SHOULD be true.
    //assert!(base.is_dir());

    let mut iter_base = base.iter();
    let mut iter_path = path.iter();

    // get rid of common components
    {
        loop {
            match (iter_base.clone().next(), iter_path.clone().next()) {
                (Some(a), Some(b)) if a == b => {
                    iter_base.next();
                    iter_path.next();
                }
                _ => break,
            }
        }
    }

    let mut rel_path = PathBuf::new();
    rel_path.extend(iter_base.map(|_| ".."));
    rel_path.push(iter_path.as_path());
    Ok(rel_path)
}

fn ignore_target_doesnt_exist(err: std::io::Error) -> std::io::Result<()> {
    if is_not_found(&err) {
        Ok(())
    } else {
        Err(err)
    }
}

fn ignore_target_exists(err: std::io::Error) -> std::io::Result<()> {
    if err.kind() == std::io::ErrorKind::AlreadyExists {
        Ok(())
    } else {
        Err(err)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    pub(crate) fn test_ctx() -> Ctx {
        let target = Path::new(env!("CARGO_MANIFEST_DIR"));
        let test_proj_dir = target.join("test_cache");
        let proj_dirs = ProjectDirs::from_path(test_proj_dir);
        proj_dirs.create_dirs().unwrap();

        Ctx {
            proj_dirs,
            options: Options { verbose: 0 },
        }
    }

    #[test]
    fn test_check_poetry_available() -> Result<()> {
        check_poetry_available()
    }

    #[test]
    fn test_install_uninstall() -> Result<()> {
        let ctx = test_ctx();

        let packages = [
            ("tuna", false),
            ("black", true),
            ("pylint", false),
            ("mypy", false),
            ("youtube-dl", false),
            ("vulture", false),
            ("conan", false),
        ];

        // The pip shim calls back to virtpy and for that we need a compiled binary.
        // cargo test doesn't automatically build the executable so we use escargot's CargoBuild
        // to do so.
        let cargo_run = escargot::CargoBuild::new().bin("virtpy").run().unwrap();

        for &(package, allow_prereleases) in &packages {
            println!("testing install of {package}");

            let base_cmd = || -> Result<_> {
                let mut cmd = assert_cmd::Command::from_std(cargo_run.command());
                cmd.arg("--project-dir")
                    .arg(ctx.proj_dirs.data())
                    .arg("-vv");
                Ok(cmd)
            };

            let mut install_cmd = base_cmd()?;
            install_cmd.arg("install").arg(package);
            if allow_prereleases {
                install_cmd.arg("--allow-prereleases");
            }

            let mut uninstall_cmd = base_cmd()?;
            uninstall_cmd.arg("uninstall").arg(package);

            install_cmd.ok()?;
            assert_ne!(
                ctx.proj_dirs.executables_list(),
                Vec::<String>::new(),
                "{package}"
            );

            uninstall_cmd.ok()?;
            assert_eq!(
                ctx.proj_dirs.executables_list(),
                Vec::<String>::new(),
                "{package}"
            );
        }
        Ok(())
    }

    #[test]
    fn relative_path_is_correct() {
        // I bet there's a library for this
        let case = |base: &str, path: &str, expected: &str| {
            assert_eq!(relative_path(base, path).unwrap(), Path::new(expected))
        };

        case("/c0/c1/a0/a1/", "/c0/c1/b0/b1", "../../b0/b1");
        case("/c0/c1/a0/a1/a2", "/c0/c1/b0/b1", "../../../b0/b1");
        case("/c0/c1/a0/a1/", "/c0/c1/b0/b1/b2", "../../b0/b1/b2");
        case("/c0/c1/a0/a1/a2", "/c0/c1/b0/b1/b2", "../../../b0/b1/b2");
        case("/c0/c1", "/c0/c1", "");
    }
}
