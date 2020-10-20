use eyre::WrapErr;
use fs_err::File;
use python_requirements::Requirement;
use rand::Rng;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::{
    collections::HashMap,
    io::BufReader,
    path::{Path, PathBuf},
};
use structopt::StructOpt;

mod python_detection;
mod python_requirements;

use fs_err::PathExt;

#[cfg(unix)]
use fs_err::os::unix::fs::symlink as symlink_dir;
#[cfg(windows)]
use fs_err::os::windows::fs::symlink_dir;

#[cfg(unix)]
use fs_err::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
use fs_err::os::windows::fs::symlink_file;

#[derive(StructOpt)]
struct Opt {
    #[structopt(subcommand)] // Note that we mark a field as a subcommand
    cmd: Command,
    #[structopt(short, parse(from_occurrences))]
    verbose: u8,
}

#[derive(StructOpt)]
enum Command {
    /// Create a new virtpy environment
    New {
        // path: Option<PathBuf>,
        /// The python to use. Either a path or an indicator of the form `python3.7` or `3.7`
        #[structopt(short, long, default_value = "3")]
        python: String,
    },
    /// Add dependency to virtpy
    Add { requirements: PathBuf },
    /// Install executable package into an isolated virtpy
    Install {
        package: Vec<String>,
        /// Reinstall, if it already exists
        #[structopt(short, long)]
        force: bool,
        #[structopt(long)]
        allow_prereleases: bool,
        /// The python to use. Either a path or an indicator of the form `python3.7` or `3.7`
        #[structopt(short, long, default_value = "3")]
        python: String,
    },
    /// Delete the virtpy of a previously installed executable package
    Uninstall { package: Vec<String> },
    /// Install the dependencies in the local .virtpy according to the poetry config
    PoetryInstall {},
    /// Find virtpys that have been moved or deleted and unneeded files in the central store.
    Gc {
        /// Delete unnecessary files
        #[structopt(long)]
        remove: bool,
    },
    /// Print paths where various files are stored
    Path(PathCmd),
    /// Show how much storage is used
    Stats,
    /// Check integrity of the files of all python modules in the internal store.
    ///
    /// If someone edited a file in any virtpy, those changes are visible in every virtpy
    /// using that file. This command detects if any changes were made to any file
    /// in the internal store.
    // FIXME: Currently, we're not verifying the file hashes on installation, so
    // if a module's RECORD is faulty, those files will also appear here
    VerifyStore,
}

#[derive(StructOpt)]
enum PathCmd {
    /// Directory where executables are placed by `virtpy install`
    Bin,
    /// Alias for `bin`
    Executables,
}

const DEFAULT_VIRTPY_PATH: &str = ".virtpy";
const INSTALLED_DISTRIBUTIONS: &str = "installed_distributions.json";
const CENTRAL_METADATA: &str = "virtpy_central_metadata";
const LINK_METADATA: &str = "virtpy_link_metadata";

fn check_output(cmd: &mut std::process::Command) -> eyre::Result<String> {
    let output = cmd.output()?;
    eyre::ensure!(output.status.success(), {
        let error = String::from_utf8_lossy(&output.stderr);
        eyre::eyre!("command failed\n    {:?}:\n{}", cmd, error)
    });
    // TODO: check out what kind error message FromUtf8Error converts into
    //       and whether it's sufficient
    String::from_utf8(output.stdout)
        .wrap_err_with(|| eyre::eyre!("output isn't valid utf8 for {:?}", cmd))
}

// probably missing prereleases and such
// TODO: check official scheme
#[derive(Copy, Clone)]
struct PythonVersion {
    major: i32,
    minor: i32,
    #[allow(unused)]
    patch: i32,
}

impl PythonVersion {
    fn as_string_without_patch(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

fn python_version(python_path: &Path) -> eyre::Result<PythonVersion> {
    let output = check_output(std::process::Command::new(python_path).arg("--version"))
        .wrap_err_with(|| {
            eyre::eyre!("couldn't get python version of `{}`", python_path.display())
        })?;
    let version = output.trim().to_owned();
    let captures = regex::Regex::new(r"Python (\d+)\.(\d+)\.(\d+)")
        .expect("invalid regex")
        .captures(&version)
        .ok_or_else(|| eyre::eyre!("failed to read python version from {:?}", version))?;

    let get_num = |idx: usize| {
        captures[idx]
            .parse::<i32>()
            .expect("failed to get capture group")
    };
    Ok(PythonVersion {
        major: get_num(1),
        minor: get_num(2),
        patch: get_num(3),
    })
}

#[derive(
    Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct DependencyHash(String);

// TODO: make into newtype
type PackageFileHash = String;

// We don't know what environments and what python versions a
// given distribution is compatible with, so we let pip decide
// what distribution is compatible and only remember afterwards
// which ones (recognized by hash) we've already installed
// for a specific python version.
// If a distribution is compatible with multiple python versions,
// our store will contain the files only once.
//
// The same distribution installed with different python versions
// might result in incompatible files.
// We currently assume they don't.
// key = python version "major.minor"
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredDistributions(HashMap<String, HashMap<DependencyHash, PathBuf>>);

impl StoredDistributions {
    fn load(proj_dirs: &ProjectDirs) -> eyre::Result<Self> {
        let file = match File::open(proj_dirs.installed_distributions_log()) {
            Ok(f) => f,
            Err(err) if is_not_found(&err) => {
                return Ok(StoredDistributions(HashMap::new()));
            }
            Err(err) => eyre::bail!(err),
        };
        let reader = BufReader::new(file);
        serde_json::from_reader(reader).wrap_err("couldn't load stored distributions")
    }

    fn save(&self, proj_dirs: &ProjectDirs) -> eyre::Result<()> {
        let path = proj_dirs.installed_distributions_log();
        File::create(&path)
            .map_err(eyre::Report::new)
            .and_then(|file|
                // NOTE: does this need a BufWriter?
                serde_json::to_writer_pretty(file, self).wrap_err("failed to serialize stored distributions") )
            .wrap_err("failed to save stored distributions")
    }
}

fn serialize_requirements_txt(reqs: &[Requirement]) -> String {
    let mut output = String::new();
    for req in reqs {
        let _ = write!(&mut output, "{}=={}", req.name, req.version);
        if let Some(marker) = req.marker.as_ref() {
            let _ = write!(&mut output, "; {}", marker);
        }
        let _ = writeln!(&mut output, " \\");
        let hashes = req
            .available_hashes
            .iter()
            .map(|hash| format!("    --hash={}", hash.0.replace("=", ":")))
            .collect::<Vec<_>>();
        let _ = writeln!(&mut output, "{}", hashes.join(" \\\n"));
    }
    output
}

fn copy_directory(from: &Path, to: &Path) {
    for dir_entry in walkdir::WalkDir::new(from) {
        let dir_entry = dir_entry.unwrap();
        let path = dir_entry.path();
        let subpath = path.strip_prefix(from).unwrap();
        let target_path = to.join(&subpath);
        if dir_entry.file_type().is_dir() {
            fs_err::create_dir(target_path).unwrap();
        } else {
            fs_err::copy(path, target_path).unwrap();
        }
    }
}

fn is_path_of_executable(path: &Path) -> bool {
    path.starts_with("bin") || path.starts_with("Scripts")
}

#[derive(PartialEq, Eq, Debug)]
struct EntryPoint {
    name: String,
    module: String,
    qualname: Option<String>,
    // optional and now deprecated
    //extras: Option<Vec<String>>
}

impl EntryPoint {
    // construct from entry_points ini entry
    fn new(key: &str, value: &str) -> Self {
        let mut it = value.split(':');
        let module = it.next().unwrap().to_owned();
        let qualname = it.next().map(<_>::to_owned);

        EntryPoint {
            name: key.to_owned(),
            module,
            qualname,
        }
    }

    fn executable_code(&self, python_path: &Path) -> (String, String) {
        (
            format!(r"#!{}", python_path.display()),
            format!(
                r"# -*- coding: utf-8 -*-
import re
import sys
from {} import {qualname}
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit({qualname}())
",
                self.module,
                qualname = self.qualname.clone().unwrap()
            ),
        )
    }

    fn generate_executable(&self, dest: &Path, python_path: &Path) -> std::io::Result<()> {
        let dest = match dest.is_dir() {
            true => dest.join(&self.name),
            false => dest.to_owned(),
        };

        let (shebang, code) = self.executable_code(&python_path);
        self._generate_executable(&dest, format!("{}\n{}", shebang, code).as_bytes())?;

        #[cfg(windows)]
        {
            // Generate .exe wrappers for python scripts.
            // This uses the same launcher as the python module "distlib", which is what pip uses
            // to generate exe wrappers.
            // The launcher needs to be concatenated with a shebang and a zip of the code to be executed.
            // The launcher code is at https://bitbucket.org/vinay.sajip/simple_launcher/

            // TODO: support 32 bit launchers and maybe GUI launchers
            use std::io::Write;
            static LAUNCHER_CODE: &[u8] = include_bytes!("../windows_exe_wrappers/t64.exe");
            let mut zip_writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::<u8>::new()));
            zip_writer.start_file("__main__.py", zip::write::FileOptions::default())?;
            write!(&mut zip_writer, "{}", code).unwrap();
            let mut wrapper = LAUNCHER_CODE.to_vec();
            wrapper.extend(shebang.as_bytes());
            wrapper.extend(b".exe");
            wrapper.extend(b"\r\n");
            wrapper.extend(zip_writer.finish()?.into_inner());
            self._generate_executable(&dest.with_extension("exe"), &wrapper)?;
        }
        Ok(())
    }

    fn _generate_executable(&self, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let mut opts = fs_err::OpenOptions::new();
        // create_new causes failure if the target already exists
        // TODO: handle error
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt;
            opts.mode(0o744);
        }

        let mut f = opts.open(dest)?;
        use std::io::Write;
        f.write_all(bytes)
    }
}

fn entrypoints(dist_info: &Path) -> Option<Vec<EntryPoint>> {
    let ini = dist_info.join("entry_points.txt");
    let ini = ini::Ini::load_from_file(ini);

    match ini {
        Err(ini::ini::Error::Io(err)) if is_not_found(&err) => return None,
        _ => (),
    };
    let ini = ini.unwrap();

    let entrypoints = ini
        .section(Some("console_scripts"))
        .map_or(vec![], |console_scripts| {
            console_scripts
                .iter()
                .map(|(key, val)| EntryPoint::new(key, val))
                .collect()
        });
    Some(entrypoints)
}

fn dist_info_dirname(name: &str, version: &str, hash: &str) -> String {
    format!("{},{},{}", name, version, hash)
}

fn register_distribution_files(
    proj_dirs: &ProjectDirs,
    install_folder: &Path,
    distribution_name: &str,
    version: &str,
    sha: String,
    stored_distributions: &mut HashMap<DependencyHash, PathBuf>,
    options: crate::Options,
) -> eyre::Result<()> {
    let dist_info_foldername = format!("{}-{}.dist-info", distribution_name, version);
    let src_dist_info = install_folder.join(&dist_info_foldername);

    let dst_dist_info_dirname = dist_info_dirname(distribution_name, version, &sha);
    let dst_dist_info = proj_dirs.dist_infos().join(&dst_dist_info_dirname);

    if dst_dist_info.exists() {
        // add it here, because it may have been installed by a different
        // python version. In that case, the current python version's list
        // may be missing this distribution.
        stored_distributions.insert(DependencyHash(sha), PathBuf::from(dst_dist_info_dirname));
        return Ok(());
    }
    if options.verbose >= 1 {
        println!("Adding {} {} to central store.", distribution_name, version);
    }

    for file in records(&src_dist_info.join("RECORD"))
        .wrap_err("couldn't find dist-info/RECORD")?
        .map(Result::unwrap)
    {
        // Sanity check. We're not caching compiled code so pip is told not to compile python code.
        // If this folder exists, something went wrong.
        debug_assert!(file.path.iter().all(|part| part != "__pycache__"));

        let path = remove_leading_parent_dirs(&file.path).unwrap_or_else(std::convert::identity);
        if is_path_of_executable(path) {
            // executables generated by pip depend either on the global python
            // or the venv they were generated for. They can't be symlinked into a virtpy
            // but have to be generated on demand.
            continue;
        }

        debug_assert_ne!(file.hash, "");

        let src = install_folder.join(path);
        let dest = proj_dirs.package_files().join(file.hash);
        if options.verbose >= 2 {
            println!("    copying {} to {}", src.display(), dest.display());
        }

        // TODO: use rename, if on same filesystem
        let res = fs_err::copy(src, dest);
        match &res {
            Err(err) if is_not_found(err) => {
                print_error_missing_file_in_record(&dist_info_foldername, &file.path)
            }
            _ => {
                res.unwrap();
            }
        };
    }

    // TODO: should try to move instead of copy, if possible
    copy_directory(&src_dist_info, &dst_dist_info);
    stored_distributions.insert(DependencyHash(sha), PathBuf::from(dst_dist_info_dirname));
    Ok(())
}

#[derive(Debug, serde::Deserialize, PartialEq, Eq, Hash, Clone)]
struct InstalledFile {
    path: PathBuf,
    hash: String,
    filesize: u64,
}

// returns all files recorded in RECORDS, except for .dist-info files
fn records(record: &Path) -> csv::Result<impl Iterator<Item = csv::Result<InstalledFile>>> {
    Ok(csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(record)?
        .into_records()
        .filter_map(|record| {
            let record = match record {
                Ok(rec) => rec,
                Err(err) => return Some(Err(err)),
            };
            let path = &record[0];
            let path = Path::new(path);
            // this isn't true, the path may be absolute but that's not supported yet
            assert!(path.is_relative());
            let first = path
                .components()
                .find_map(|comp| match comp {
                    std::path::Component::Normal(path) => Some(path),
                    _ => None,
                })
                .unwrap();
            let is_dist_info = first
                .to_owned()
                .into_string()
                .unwrap()
                .ends_with(".dist-info");

            if is_dist_info {
                return None;
            }

            Some(record.deserialize(None))
        }))
}

fn install_and_register_distributions(
    python_path: &Path,
    proj_dirs: &ProjectDirs,
    distribs: &[Requirement],
    python_version: PythonVersion,
    options: Options,
) -> eyre::Result<()> {
    if options.verbose >= 1 {
        println!("Adding {} new distributions", distribs.len());
    }
    if distribs.is_empty() {
        return Ok(());
    }

    let tmp_dir = tempdir::TempDir::new("virtpy")?;
    let tmp_requirements = tmp_dir.as_ref().join("__tmp_requirements.txt");
    let reqs = serialize_requirements_txt(distribs);
    fs_err::write(&tmp_requirements, reqs)?;
    let output = std::process::Command::new(python_path)
        .args(&["-m", "pip", "install", "--no-deps", "--no-compile", "-r"])
        .arg(&tmp_requirements)
        .arg("-t")
        .arg(tmp_dir.as_ref())
        .args(&["-v"])
        .output()?;
    if !output.status.success() {
        panic!(
            "pip error:\n{}",
            std::str::from_utf8(&output.stderr).unwrap()
        );
    }

    let pip_log = String::from_utf8(output.stdout)?;

    let new_distribs = newly_installed_distributions(&pip_log);

    if options.verbose >= 1 {
        if new_distribs.len() != distribs.len() {
            // either an error or a sign that the filters in new_dependencies()
            // need to be improved
            println!(
                "Only found {} of {} distributions",
                new_distribs.len(),
                distribs.len()
            );

            let _ = fs_err::write(proj_dirs.data().join("pip.log"), pip_log);
        }
    }
    if options.verbose >= 2 {
        for distrib in new_distribs.iter() {
            println!(
                "    New distribution: {}=={}, {}",
                distrib.name, distrib.version, distrib.sha
            );
        }
    }

    let mut all_stored_distributions = StoredDistributions::load(proj_dirs)?;
    let stored_distributions = all_stored_distributions
        .0
        .entry(python_version.as_string_without_patch())
        .or_default();
    for distrib in new_distribs {
        register_distribution_files(
            proj_dirs,
            tmp_dir.as_ref(),
            &distrib.name,
            &distrib.version,
            distrib.sha.clone(),
            stored_distributions,
            options,
        ).wrap_err_with(|| eyre::eyre!("failed to add distribution files for {} {}", distrib.name, distrib.version))?;
    }

    all_stored_distributions.save(proj_dirs)?;

    Ok(())
}

fn new_dependencies(
    requirements: &[Requirement],
    proj_dirs: &ProjectDirs,
    python_version: PythonVersion,
) -> eyre::Result<Vec<Requirement>> {
    let stored_distributions = StoredDistributions::load(proj_dirs)?;
    let existing_deps = match stored_distributions
        .0
        .get(&python_version.as_string_without_patch())
    {
        Some(deps) => deps,
        None => return Ok(requirements.to_owned()),
    };

    Ok(requirements
        .iter()
        .filter(|req| {
            (req.marker
                .as_ref()
                .map_or(true, |cond| cond.matches_system()))
                && !req
                    .available_hashes
                    .iter()
                    .any(|hash| existing_deps.contains_key(hash))
        })
        .cloned()
        .collect::<Vec<_>>())
}

// toplevel options
#[derive(Copy, Clone)]
struct Options {
    verbose: u8,
}

struct ProjectDirs {
    data_dir: PathBuf,
}

impl ProjectDirs {
    fn new() -> Option<Self> {
        directories::ProjectDirs::from("", "", "virtpy").map(|proj_dirs| Self {
            data_dir: proj_dirs.data_dir().to_owned(),
        })
    }

    #[cfg(test)]
    fn from_path(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn create_dirs(&self) -> std::io::Result<()> {
        fs_err::create_dir_all(self.data())?;
        for path in &[
            self.installations(),
            self.dist_infos(),
            self.package_files(),
            self.executables(),
            self.virtpys(),
        ] {
            fs_err::create_dir(path).or_else(ignore_target_exists)?;
        }
        Ok(())
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

    fn dist_infos(&self) -> PathBuf {
        self.data().join("dist-infos")
    }

    fn package_files(&self) -> PathBuf {
        self.data().join("package_files")
    }

    fn executables(&self) -> PathBuf {
        self.data().join("bin")
    }

    fn installed_distributions_log(&self) -> PathBuf {
        self.data().join(INSTALLED_DISTRIBUTIONS)
    }

    fn package_folder(&self, package: &str) -> PathBuf {
        self.installations().join(&format!("{}.virtpy", package))
    }

    fn installed_distributions(&self) -> impl Iterator<Item = Distribution> + '_ {
        self.dist_infos()
            .read_dir()
            .unwrap()
            .map(Result::unwrap)
            .map(|dist_info_entry| {
                Distribution::from_store_name(
                    dist_info_entry
                        .path()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                )
            })
    }
}

lazy_static::lazy_static! {
    static ref DIST_INFO_PATTERN: regex::Regex = {
        regex::Regex::new(r"([a-zA-Z_][a-zA-Z0-9_-]*)-(\d*!.*|\d*\..*)\.dist-info").unwrap()
    };
}

fn package_info_from_dist_info_dirname(dirname: &str) -> (&str, &str) {
    let captures = DIST_INFO_PATTERN.captures(dirname).unwrap();
    let distrib_name = captures.get(1).unwrap();
    let version = captures.get(2).unwrap();
    (distrib_name.as_str(), version.as_str())
}

struct VirtpyBacking {
    location: PathBuf,
    python_version: PythonVersion,
}

impl VirtpyPaths for VirtpyBacking {
    fn location(&self) -> &Path {
        &self.location
    }

    fn python_version(&self) -> PythonVersion {
        self.python_version
    }
}

impl VirtpyBacking {
    fn from_path(location: PathBuf) -> Self {
        Self {
            python_version: python_version(&python_path(&location)).unwrap(),
            location,
        }
    }
}

fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    let opt = Opt::from_args();
    let options = Options {
        verbose: opt.verbose,
    };

    let proj_dirs = ProjectDirs::new().unwrap();
    proj_dirs.create_dirs()?;

    match opt.cmd {
        Command::Add { requirements } => {
            fn add_requirements(
                proj_dirs: &ProjectDirs,
                options: Options,
                requirements: PathBuf,
            ) -> eyre::Result<()> {
                let virtpy_path = DEFAULT_VIRTPY_PATH.as_ref();
                let virtpy = CheckedVirtpy::new(virtpy_path)?;
                let requirements = fs_err::read_to_string(requirements)?;
                let requirements = python_requirements::read_requirements_txt(&requirements);

                virtpy_add_dependencies(&proj_dirs, &virtpy, requirements, None, options)?;
                Ok(())
            }

            add_requirements(&proj_dirs, options, requirements)
                .wrap_err("failed to add requirements")?;
        }
        Command::New { python } => {
            let path = PathBuf::from(DEFAULT_VIRTPY_PATH);
            python_detection::detect(&python)
                .and_then(|python_path| create_virtpy(&proj_dirs, &python_path, &path, None))
                .wrap_err("failed to create virtpy")?;
        }
        Command::Install {
            package,
            force,
            allow_prereleases,
            python,
        } => {
            for package in package {
                println!("installing {}...", package);
                match install_executable_package(
                    &proj_dirs,
                    options,
                    &package,
                    force,
                    allow_prereleases,
                    &python,
                ) {
                    Ok(InstalledStatus::NewlyInstalled) => println!("installed {}.", package),
                    Ok(InstalledStatus::AlreadyInstalled) => {
                        println!("package is already installed.")
                    }
                    Err(err) => eprintln!("{:?}", err),
                }
            }
        }
        Command::Uninstall { package } => {
            for package in package {
                match delete_executable_virtpy(&proj_dirs, &package)
                    .wrap_err(eyre::eyre!("failed to uninstall {}", package))
                {
                    Ok(()) => println!("uninstalled {}.", package),
                    Err(err) => eprintln!("{:?}", err),
                }
            }
        }
        Command::PoetryInstall {} => {
            fn poetry_install(proj_dirs: &ProjectDirs, options: Options) -> eyre::Result<()> {
                let virtpy_path: &Path = DEFAULT_VIRTPY_PATH.as_ref();
                let python_path = python_detection::detect("3")?;
                let virtpy = match virtpy_path.exists() {
                    true => {
                        let virtpy = CheckedVirtpy::new(virtpy_path)
                            .wrap_err("found an existing virtpy but couldn't verify it")?;

                        virtpy
                            .reset(proj_dirs)
                            .wrap_err("found an existing virtpy but failed when resetting it")?
                    }
                    false => {
                        // It would be better to respect the python version setting in pyproject.toml
                        // If this were meant for production, it should use the poetry project name for the prompt
                        create_virtpy(&proj_dirs, &python_path, &virtpy_path, None)
                            .wrap_err("no virtpy exists and failed to create one")?
                    }
                };
                let requirements =
                    python_requirements::poetry_get_requirements(&python_path, &find_poetry()?, Path::new("."), true)?;
                virtpy_add_dependencies(&proj_dirs, &virtpy, requirements, None, options)?;
                Ok(())
            }

            poetry_install(&proj_dirs, options)
                .wrap_err("failed to install dependencies from poetry project")?;
        }
        Command::Gc { remove } => {
            let mut danglers = vec![];
            for virtpy in proj_dirs.virtpys().read_dir().unwrap() {
                let virtpy = virtpy.unwrap();
                assert!(virtpy.file_type().unwrap().is_dir());
                let path = virtpy.path();

                match virtpy_status(&path) {
                    Ok(VirtpyStatus::Ok { .. }) => (),
                    Ok(VirtpyStatus::Orphaned { link }) => danglers.push((path, link)),
                    Err(err) => println!("failed to check {}: {}", path.display(), err),
                };
            }

            if danglers.len() != 0 {
                println!("found {} missing virtpys.", danglers.len());

                if remove {
                    for (backing, link) in danglers {
                        debug_assert!(virtpy_link_target(&link)
                            .map_or(true, |link_target| link_target != backing));
                        delete_virtpy_backing(&backing).unwrap();
                    }
                } else {
                    println!("If you've moved some of these, recreate new ones in their place as they'll break when the orphaned backing stores are deleted.\nRun `virtpy gc --remove` to delete orphans\n");

                    for (target, virtpy_gone_awol) in danglers {
                        println!("{} => {}", virtpy_gone_awol.display(), target.display());
                    }
                }
            }

            {
                let unused_dists = unused_distributions(&proj_dirs).collect::<Vec<_>>();
                if !unused_dists.is_empty() {
                    println!("found {} modules without users.", unused_dists.len());

                    if remove {
                        let mut stored_distribs = StoredDistributions::load(&proj_dirs)?;

                        let dist_info_dir = proj_dirs.dist_infos();
                        for dist in unused_dists {
                            let path = dist.path(&proj_dirs);
                            assert!(path.starts_with(&dist_info_dir));

                            println!("Removing {} {} ({})", dist.name, dist.version, dist.sha);

                            let res = fs_err::remove_dir_all(path);

                            // Remove distribution from list of installed distributions, for all
                            // python versions.
                            // Save after each attempted removal in case a bug causes the removal to fail prematurely
                            let hash = DependencyHash(dist.sha);
                            for python_specific_stored_distribs in stored_distribs.0.values_mut() {
                                python_specific_stored_distribs.remove(&hash);
                            }
                            stored_distribs
                                .save(&proj_dirs)
                                .wrap_err("failed to save stored distributions")?;

                            res.unwrap();
                        }
                    }
                }
            }

            {
                let unused_package_files = unused_package_files(&proj_dirs).collect::<Vec<_>>();
                if !unused_package_files.is_empty() {
                    println!(
                        "found {} package files without distribution dependents.",
                        unused_package_files.len()
                    );

                    if remove {
                        let package_files_dir = proj_dirs.package_files();
                        for file in unused_package_files {
                            assert!(file.starts_with(&package_files_dir));
                            if options.verbose >= 1 {
                                println!("Removing {}", file.display());
                            }
                            fs_err::remove_file(file).unwrap();
                        }
                    }
                }
            }
        }
        Command::Path(PathCmd::Bin) | Command::Path(PathCmd::Executables) => {
            println!("{}", proj_dirs.executables().display());
        }
        Command::Stats => {
            print_stats(&proj_dirs, options);
        }
        Command::VerifyStore => {
            print_verify_store(&proj_dirs);
        }
    }

    Ok(())
}

enum InstalledStatus {
    NewlyInstalled,
    AlreadyInstalled,
}

fn install_executable_package(
    proj_dirs: &ProjectDirs,
    options: Options,
    package: &str,
    force: bool,
    allow_prereleases: bool,
    python: &str,
) -> eyre::Result<InstalledStatus> {
    let package_folder = proj_dirs.package_folder(&package);

    let python_path = python_detection::detect(&python)?;

    if package_folder.exists() {
        if force {
            delete_executable_virtpy(&proj_dirs, &package)?;
        } else {
            return Ok(InstalledStatus::AlreadyInstalled);
        }
    }

    let poetry_path = find_poetry()?;

    let requirements = python_requirements::get_requirements(&python_path, &poetry_path, &package, allow_prereleases)?;

    let virtpy = create_virtpy(&proj_dirs, &python_path, &package_folder, None)?;

    // if anything goes wrong, try to delete the incomplete installation
    let virtpy = scopeguard::guard(virtpy, |virtpy| {
        let _ = virtpy.delete();
    });

    virtpy_add_dependencies(&proj_dirs, &virtpy, requirements, Some(package), options)?;

    // if everything succeeds, keep the venv
    std::mem::forget(virtpy);
    Ok(InstalledStatus::NewlyInstalled)
}

fn print_verify_store(proj_dirs: &ProjectDirs) {
    // TODO: if there are errors, link them back to their original distribution
    let mut any_error = false;
    for file in proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
    {
        // the path is also the hash
        let path = file.path();
        let mut file = fs_err::File::open(&path).unwrap();
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher).unwrap();
        let hash = hasher.finalize();

        let base64_hash = base64::encode_config(&hash, base64::URL_SAFE_NO_PAD);
        if base64_hash
            != path
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .strip_prefix("sha256=")
                .unwrap()
        {
            println!(
                "doesn't match hash: {}, hash = {}",
                path.display(),
                base64_hash
            );
            any_error = true;
        }
    }
    if !any_error {
        println!("everything valid");
    }
}

fn print_stats(proj_dirs: &ProjectDirs, options: Options) {
    let total_size: u64 = proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| entry.metadata().unwrap().len())
        .sum();

    let distribution_files = files_of_distribution(proj_dirs);
    let distribution_dependents = distributions_dependents(proj_dirs);

    let total_size_with_duplicates = distribution_dependents
        .iter()
        .map(|(distr, dependents)| distribution_files[distr].1 * dependents.len() as u64)
        .sum::<u64>();

    println!("total space used: {}", total_size);
    println!(
        "total space used with duplication: {}",
        total_size_with_duplicates
    );

    println!(
        "total space saved: {}",
        total_size_with_duplicates - total_size
    );

    if options.verbose >= 1 {
        println!();
        for (distr, dependents) in distribution_dependents {
            println!(
                "{:30} {} dependents    ({})",
                format!("{} {}", distr.name, distr.version,),
                dependents.len(),
                distr.sha
            );
            if options.verbose >= 2 {
                for dependent in dependents {
                    let link_location = virtpy_link_location(&dependent).unwrap();
                    print!("    {}", link_location.display());
                    if options.verbose >= 3 {
                        print!("  =>  {}", dependent.display());
                    }
                    println!();
                }
            }
        }
    }
}

fn file_dependents<'a>(
    proj_dirs: &ProjectDirs,
    distribution_files: &HashMap<Distribution, (Vec<InstalledFile>, u64)>,
) -> HashMap<PackageFileHash, Vec<Distribution>> {
    let mut dependents = HashMap::new();

    for file in proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|dir_entry| {
            dir_entry
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
    {
        let hash = file;
        dependents.entry(hash).or_default();
    }

    for (distribution, (records, _)) in distribution_files.iter() {
        for record in records {
            dependents
                .entry(record.hash.clone())
                .or_insert_with(Vec::new)
                .push(distribution.clone());
        }
    }
    dependents
}

// return value: path to virtpy
fn distributions_dependents(proj_dirs: &ProjectDirs) -> HashMap<Distribution, Vec<PathBuf>> {
    let mut distributions_dependents = HashMap::new();

    // Add all distributions to map without dependencies.
    // Orphaned distributions would otherwise be missed.
    for distr in proj_dirs.installed_distributions() {
        distributions_dependents.entry(distr).or_default();
    }

    for virtpy_path in proj_dirs
        .virtpys()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| entry.path())
    {
        let virtpy_dirs = VirtpyBacking::from_path(virtpy_path.clone());
        for distr in distributions_used(virtpy_dirs) {
            // if the data directory is in a consistent state, the keys are guaranteed to exist already
            debug_assert!(distributions_dependents.contains_key(&distr));
            distributions_dependents
                .entry(distr)
                .or_insert_with(Vec::new)
                .push(virtpy_path.clone());
        }
    }

    distributions_dependents
}

// Find distributions in $DATA_DIR/dist-infos/ and read their files from their RECORD file.
// Also computes the total size of all distribution files
fn files_of_distribution(
    proj_dirs: &ProjectDirs,
) -> HashMap<Distribution, (Vec<InstalledFile>, u64)> {
    proj_dirs
        .installed_distributions()
        .map(|distribution| {
            let records = distribution
                .records(proj_dirs)
                .unwrap()
                .map(Result::unwrap)
                .filter(|record| {
                    // FIXME: files with ../../
                    proj_dirs.package_files().join(&record.hash).exists()
                })
                .collect::<Vec<_>>();

            let total_size = records.iter().map(|record| record.filesize).sum::<u64>();
            assert_ne!(total_size, 0);
            (distribution, (records, total_size))
        })
        .collect()
}

fn distributions_used(virtpy_dirs: VirtpyBacking) -> impl Iterator<Item = Distribution> {
    virtpy_dirs
        .dist_infos()
        .map(|dist_info_path| dist_info_path.read_link().unwrap())
        .map(|store_dist_info| {
            Distribution::from_store_name(store_dist_info.file_name().unwrap().to_str().unwrap())
        })
}

fn unused_distributions(proj_dirs: &ProjectDirs) -> impl Iterator<Item = Distribution> + '_ {
    let distribution_dependents = distributions_dependents(proj_dirs);
    distribution_dependents
        .into_iter()
        .filter(|(_, dependents)| dependents.is_empty())
        .map(|(distribution, _)| distribution)
}

fn unused_package_files(proj_dirs: &ProjectDirs) -> impl Iterator<Item = PathBuf> {
    let distribution_files = files_of_distribution(proj_dirs);
    let file_dependents = file_dependents(proj_dirs, &distribution_files);
    let package_files = proj_dirs.package_files();
    file_dependents
        .into_iter()
        .filter(|(_, dependents)| dependents.is_empty())
        .map(move |(file, _)| package_files.join(file))
}

#[must_use]
fn delete_global_package_executables(
    proj_dirs: &ProjectDirs,
    virtpy_dirs: &VirtpyBacking,
    package: &str,
) -> impl Iterator<Item = eyre::Result<()>> {
    let dist_info = virtpy_dirs.dist_info(package).unwrap();

    // FIXME: Install all executables from a package and then also delete them all.
    let executables = entrypoints(&dist_info)
        .expect("couldn't find entry_points.txt")
        .into_iter()
        .map(|ep| ep.name)
        .collect::<Vec<_>>();
    // let executables = records(&dist_info.join("RECORD"))
    //     .unwrap()
    //     .map(Result::unwrap)
    //     .flat_map(|record| {
    //         remove_leading_parent_dirs(&record.path)
    //             .ok()
    //             .map(ToOwned::to_owned)
    //     })
    //     .filter(|path| is_path_of_executable(path))
    //     .map(|path| path.file_name().unwrap().to_owned())
    //     .collect::<Vec<_>>();

    let exe_dir = proj_dirs.executables();
    let executables = executables.into_iter();

    let executables = {
        #[cfg(unix)]
        {
            executables.map(move |executable| exe_dir.join(executable))
        }

        #[cfg(windows)]
        {
            executables.flat_map(move |executable| {
                let path = exe_dir.join(executable);
                vec![path.with_extension("exe"), path]
            })
        }
    };

    executables.map(|path| {
        fs_err::remove_file(&path)
            // Necessary when deleting from RECORD and when we're not installing all scripts
            // as pip does (e.g. because we're leaving out package.data scripts)
            .or_else(ignore_target_doesnt_exist)
            .wrap_err_with(|| eyre::eyre!("failed to remove {}", path.display()))
    })
}

fn virtpy_add_dependencies(
    proj_dirs: &ProjectDirs,
    virtpy: &CheckedVirtpy,
    requirements: Vec<Requirement>,
    //python_version: PythonVersion,
    install_global_executable: Option<&str>,
    options: Options,
) -> eyre::Result<()> {
    let new_deps = new_dependencies(&requirements, proj_dirs, virtpy.python_version)?;

    // The virtpy doesn't contain pip so get the appropriate global python
    let python_path = virtpy.global_python()?;

    install_and_register_distributions(
        &python_path,
        proj_dirs,
        &new_deps,
        virtpy.python_version,
        options,
    )?;

    link_requirements_into_virtpy(
        proj_dirs,
        virtpy,
        requirements,
        options,
        install_global_executable,
    )
    .wrap_err("failed to add packages to virtpy")
}

fn is_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

fn delete_executable_virtpy(proj_dirs: &ProjectDirs, package: &str) -> eyre::Result<()> {
    let virtpy_path = proj_dirs.package_folder(&package);
    let virtpy = CheckedVirtpy::new(&virtpy_path)?;
    delete_global_package_executables(&proj_dirs, &virtpy.virtpy_backing(), &package)
        .for_each(Result::unwrap);

    virtpy.delete()
}

fn delete_virtpy_backing(backing_folder: &Path) -> std::io::Result<()> {
    assert!(backing_folder.join(CENTRAL_METADATA).exists());
    fs_err::remove_dir_all(backing_folder)
}

fn create_virtpy(
    project_dirs: &ProjectDirs,
    python_path: &Path,
    path: &Path,
    prompt: Option<String>,
) -> eyre::Result<CheckedVirtpy> {
    let mut rng = rand::thread_rng();

    // Generate a random id for the virtpy.
    // This should only take 1 attempt, but it's theoretically possible
    // for the id to collide with a previous one, so check and retry if that's the case, but not forever.
    let n_max_attempts = 10;
    let random_path_gen = std::iter::repeat_with(|| {
        let id = std::iter::repeat_with(|| rng.sample(rand::distributions::Alphanumeric))
            .take(12)
            .collect::<String>();
        project_dirs.virtpys().join(id)
    });

    let central_path = random_path_gen
        .take(n_max_attempts)
        .find(|path| !path.exists())
        .ok_or_else(|| {
            eyre::eyre!(
                "failed to generate an unused virtpy path in {} attempts",
                n_max_attempts
            )
        })?;

    let prompt = prompt.as_deref().unwrap_or(DEFAULT_VIRTPY_PATH);
    _create_virtpy(central_path, python_path, path, prompt)
}

fn create_virtpy_with_id(
    project_dirs: &ProjectDirs,
    python_path: &Path,
    path: &Path,
    prompt: &str,
    id: &str,
) -> eyre::Result<CheckedVirtpy> {
    let central_path = project_dirs.virtpys().join(id);
    assert!(!central_path.exists());
    _create_virtpy(central_path, python_path, path, prompt)
}

fn _create_virtpy(
    central_path: PathBuf,
    python_path: &Path,
    path: &Path,
    prompt: &str,
) -> eyre::Result<CheckedVirtpy> {
    _create_bare_venv(python_path, &central_path, prompt)?;

    fs_err::create_dir(path)?;
    for entry in central_path.read_dir()? {
        let entry = entry?;
        let target = path.join(entry.file_name());
        let filetype = entry.file_type()?;
        if filetype.is_dir() {
            symlink_dir(&entry.path(), &target)?;
        } else if filetype.is_file() {
            symlink_file(&entry.path(), &target)?;
        } else if filetype.is_symlink() {
            // the only symlink should be lib64 pointing at lib
            // assert_eq!(entry.file_name(), "lib64");
            symlink_dir(&entry.path(), &target)?;
        }
    }

    let abs_path = path
        .fs_err_canonicalize()?
        .into_os_string()
        .into_string()
        .unwrap();
    {
        let metadata_dir = central_path.join(CENTRAL_METADATA);
        fs_err::create_dir(&metadata_dir)?;
        fs_err::write(metadata_dir.join("link_location"), &abs_path)?;
    }

    {
        let link_metadata_dir = path.join(LINK_METADATA);
        fs_err::create_dir(&link_metadata_dir)?;
        fs_err::write(link_metadata_dir.join("link_location"), &abs_path)?;

        debug_assert!(central_path.is_absolute());
        fs_err::write(
            link_metadata_dir.join("central_location"),
            central_path.as_os_str().to_str().unwrap(),
        )?;
    }

    Ok(CheckedVirtpy {
        link: path.to_owned(),
        backing: central_path,
        // Not all users of this function may need the python version, but it's
        // cheap to get and simpler to just always query.
        // Could be easily replaced with a token-struct that could be converted
        // to a full CheckedVirtpy on demand.
        python_version: python_version(python_path)?,
    })
}

#[allow(unused)]
enum VirtpyLinkStatus {
    Ok { matching_virtpy: PathBuf },
    WrongLocation { should: PathBuf, actual: PathBuf },
    Dangling { target: PathBuf },
}

fn virtpy_link_status(virtpy_link_path: &Path) -> eyre::Result<VirtpyLinkStatus> {
    let supposed_location = virtpy_link_supposed_location(virtpy_link_path)
        .wrap_err("failed to read original location of virtpy")?;
    if !paths_match(virtpy_link_path, &supposed_location).unwrap() {
        return Ok(VirtpyLinkStatus::WrongLocation {
            should: supposed_location,
            actual: virtpy_link_path.to_owned(),
        });
    }

    let target = virtpy_link_target(virtpy_link_path).wrap_err("failed to find virtpy backing")?;
    if !target.exists() {
        return Ok(VirtpyLinkStatus::Dangling {
            target: target.clone(),
        });
    }

    Ok(VirtpyLinkStatus::Ok {
        matching_virtpy: target,
    })
}

fn paths_match(virtpy: &Path, link_target: &Path) -> eyre::Result<bool> {
    Ok(virtpy.fs_err_canonicalize()? == link_target.fs_err_canonicalize()?)
}

fn virtpy_link_location(virtpy: &Path) -> std::io::Result<PathBuf> {
    let backlink = virtpy.join(CENTRAL_METADATA).join("link_location");
    fs_err::read_to_string(backlink).map(PathBuf::from)
}

fn virtpy_link_target(virtpy_link: &Path) -> std::io::Result<PathBuf> {
    let link = virtpy_link.join(LINK_METADATA).join("central_location");
    fs_err::read_to_string(link).map(PathBuf::from)
}

fn virtpy_link_supposed_location(virtpy_link: &Path) -> std::io::Result<PathBuf> {
    let link = virtpy_link.join(LINK_METADATA).join("link_location");
    fs_err::read_to_string(link).map(PathBuf::from)
}

#[derive(Debug)]
enum VirtpyStatus {
    Ok { matching_link: PathBuf },
    Orphaned { link: PathBuf },
}

fn virtpy_status(virtpy_path: &Path) -> eyre::Result<VirtpyStatus> {
    let link_location = virtpy_link_location(virtpy_path)
        .wrap_err("failed to read location of corresponding virtpy")?;

    let link_target = virtpy_link_target(&link_location);

    if let Err(err) = &link_target {
        if is_not_found(err) {
            return Ok(VirtpyStatus::Orphaned {
                link: link_location,
            });
        }
    }

    let link_target = link_target
        .map(PathBuf::from)
        .wrap_err("failed to read virtpy link target through backlink")?;

    if !paths_match(virtpy_path, &link_target).unwrap() {
        return Ok(VirtpyStatus::Orphaned {
            link: link_location,
        });
    }

    Ok(VirtpyStatus::Ok {
        matching_link: link_location,
    })
}
fn _create_bare_venv(python_path: &Path, path: &Path, prompt: &str) -> eyre::Result<()> {
    check_output(
        std::process::Command::new(python_path)
            .args(&["-m", "venv", "--without-pip", "--prompt", prompt])
            .arg(&path)
            .stdout(std::process::Stdio::null()),
    )
    .map(drop)
    .wrap_err_with(|| eyre::eyre!("failed to create virtpy {}", path.display()))
}

fn find_poetry() -> eyre::Result<PathBuf> {
    // we cannot execute poetry directly, because it is only distributed as a python
    // file and as a batch.
    // `std::process::Command::new("poetry")` fails to find an executable.
    // We can however find the python file and a python executable and then invoke python on
    // poetry.
    pathsearch::find_executable_in_path("poetry")
        .ok_or_else(|| eyre::eyre!("this command requires poetry to be installed and on the PATH. (https://github.com/python-poetry/poetry)"))
}

struct CheckedVirtpy {
    link: PathBuf,
    backing: PathBuf,
    python_version: PythonVersion,
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
    let entry_name = dist_info.file_name().unwrap().to_str().unwrap();
    let (distrib_name, _version) = package_info_from_dist_info_dirname(entry_name);
    distrib_name == package
}

trait VirtpyPaths {
    fn location(&self) -> &Path;
    fn python_version(&self) -> PythonVersion;

    fn executables(&self) -> PathBuf {
        executables_path(self.location())
    }

    fn python(&self) -> PathBuf {
        python_path(self.location())
    }

    fn dist_info(&self, package: &str) -> Option<PathBuf> {
        self.dist_infos()
            .find(|path| dist_info_matches_package(path, package))
    }

    fn dist_infos(&self) -> Box<dyn Iterator<Item = PathBuf>> {
        Box::new(
            self.site_packages()
                .read_dir()
                .unwrap()
                .map(Result::unwrap)
                .map(|dir_entry| dir_entry.path())
                .filter(|path| {
                    path.file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .ends_with(".dist-info")
                }),
        )
    }

    fn site_packages(&self) -> PathBuf {
        if cfg!(unix) {
            self.location().join(format!(
                "lib/python{}/site-packages",
                self.python_version().as_string_without_patch()
            ))
        } else {
            self.location().join("Lib/site-packages")
        }
    }
}

impl VirtpyPaths for CheckedVirtpy {
    fn location(&self) -> &Path {
        &self.link
    }

    fn python_version(&self) -> PythonVersion {
        self.python_version
    }
}

impl CheckedVirtpy {
    fn new(virtpy_link: &Path) -> eyre::Result<Self> {
        match virtpy_link_status(virtpy_link).wrap_err("failed to verify virtpy")? {
            VirtpyLinkStatus::WrongLocation { should, .. } => Err(eyre::eyre!(
                "virtpy copied or moved from {}",
                should.display()
            )),
            VirtpyLinkStatus::Dangling { target } => Err(eyre::eyre!(
                "backing storage for virtpy not found: {}",
                target.display()
            )),
            VirtpyLinkStatus::Ok { matching_virtpy } => Ok(CheckedVirtpy {
                link: virtpy_link.to_owned(),
                backing: matching_virtpy,
                python_version: python_version(&python_path(virtpy_link))?,
            }),
        }
        .wrap_err_with(|| {
            eyre::eyre!(
                "the virtpy `{}` is broken, please recreate it.",
                virtpy_link.display(),
            )
        })
    }

    // Returns the path of the python installation on which this
    // this virtpy builds
    fn global_python(&self) -> eyre::Result<PathBuf> {
        // FIXME: On windows, the virtpy python is a copy, so there's no symlink to resolve.
        //        We need to take the version and then do a search for the real python.
        #[cfg(unix)]
        {
            self.python().fs_err_canonicalize().wrap_err_with(|| {
                eyre::eyre!(
                    "failed to find path of the global python used by virtpy at {}",
                    self.link.display()
                )
            })
        }

        #[cfg(windows)]
        {
            let version = python_version(&self.python())?;
            python_detection::detect(&version.as_string_without_patch())
        }
    }

    fn id(&self) -> &str {
        self.backing.file_name().unwrap().to_str().unwrap()
    }

    // read prompt from pyenv.cfg, if it exists
    // virtpys always have a custom prompt, but only python3.8+
    // stores it in the pyvenv.cfg.
    //
    // could also do this at initialization and read the python version from there
    // at the same time
    fn prompt(&self) -> eyre::Result<String> {
        let ini = self.location().join("pyvenv.cfg");
        let ini = ini::Ini::load_from_file(ini)?;

        Ok(ini
            .general_section()
            .get("prompt")
            .unwrap_or(DEFAULT_VIRTPY_PATH)
            .to_owned())
    }

    fn delete(self) -> eyre::Result<()> {
        fs_err::remove_dir_all(self.location())?;
        delete_virtpy_backing(&self.backing)?;
        Ok(())
    }

    fn reset(self, proj_dirs: &ProjectDirs) -> eyre::Result<Self> {
        // Reset virtpy by deleting it.
        // keep the id the same so currently activated environments stay valid.
        let id = self.id().to_owned();
        let python_path = self.global_python()?;
        let virtpy_path = self.location().to_owned();
        let prompt = self.prompt()?;
        // delete the old virtpy so the id is freed.
        // TODO: on failure, the old state should be kept
        self.delete()?;
        create_virtpy_with_id(&proj_dirs, &python_path, &virtpy_path, &prompt, &id)
    }

    fn virtpy_backing(&self) -> VirtpyBacking {
        VirtpyBacking {
            location: self.backing.clone(),
            python_version: self.python_version,
        }
    }
}

fn link_requirements_into_virtpy(
    proj_dirs: &ProjectDirs,
    virtpy: &CheckedVirtpy,
    mut requirements: Vec<Requirement>,
    options: Options,
    install_global_executable: Option<&str>,
) -> eyre::Result<()> {
    // FIXME: when new top-level directories are created in the central venv,
    //        they should also be symlinked in the virtpy
    let site_packages = virtpy.site_packages();

    requirements.retain(|req| {
        req.marker
            .as_ref()
            .map_or(true, |cond| cond.matches_system())
    });
    let requirements = requirements;

    let stored_distributions = StoredDistributions::load(proj_dirs)?;
    let existing_deps = stored_distributions
        .0
        .get(&virtpy.python_version.as_string_without_patch())
        .cloned()
        .unwrap_or_default();
    for distribution in requirements {
        // find compatible hash
        let dist_info_path = match distribution
            .available_hashes
            .iter()
            .find_map(|hash| existing_deps.get(&hash))
        {
            Some(path) => proj_dirs.dist_infos().join(path),
            None => {
                // return Err(format!(
                //     "failed to find dist_info for distribution: {:?}",
                //     distribution
                // )
                // .into());
                println!(
                    "failed to find dist_info for distribution: {} {} {}",
                    distribution.name,
                    distribution.version,
                    distribution
                        .marker
                        .map_or(String::new(), |m| format!(", {}", m))
                );
                if options.verbose >= 2 {
                    println!("available_hashes: {:#?}", distribution.available_hashes);
                }
                continue;
            }
        };

        let dist_info_foldername =
            format!("{}-{}.dist-info", distribution.name, distribution.version);
        let target = site_packages.join(&dist_info_foldername);
        if options.verbose >= 1 {
            println!(
                "symlinking dist info from {} to {}",
                dist_info_path.display(),
                target.display()
            );
        }

        // TODO: create directory and hardlink contents
        symlink_dir(&dist_info_path, &target)
            .or_else(ignore_target_exists)
            .unwrap();

        for record in records(&dist_info_path.join("RECORD"))
            .unwrap()
            .map(Result::unwrap)
        {
            let dest = match remove_leading_parent_dirs(&record.path) {
                Ok(path) => {
                    let toplevel_dirs = ["bin", "Scripts", "include", "lib", "lib64", "share"];
                    let starts_with_venv_dir =
                        toplevel_dirs.iter().any(|dir| path.starts_with(dir));
                    if !starts_with_venv_dir {
                        println!(
                            "{}: attempted file placement outside virtpy, ignoring: {}",
                            distribution.name,
                            record.path.display()
                        );
                        continue;
                    }

                    // executables need to be generated on demand
                    if is_path_of_executable(path) {
                        continue;
                    }

                    let dest = virtpy.backing.join(path);
                    if path.starts_with("include") || path.starts_with("share") {
                        fs_err::create_dir_all(dest.parent().unwrap()).unwrap();
                    }
                    dest
                }
                Err(path) => {
                    let dest = site_packages.join(path);
                    let dir = dest.parent().unwrap();
                    fs_err::create_dir_all(&dir).unwrap();
                    dest
                }
            };

            let src = proj_dirs.package_files().join(record.hash);
            match fs_err::hard_link(&src, &dest) {
                Ok(_) => (),
                // TODO: can this error exist? Docs don't say anything about this being a failure
                //       condition
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(err) if is_not_found(&err) => {
                    print_error_missing_file_in_record(&dist_info_foldername, &src)
                }
                Err(err) => panic!(
                    "failed to hardlink file from {} to {}: {}",
                    src.display(),
                    dest.display(),
                    err
                ),
            };
        }

        let install_global_executable = install_global_executable == Some(&distribution.name[..]);
        let entrypoints = match (entrypoints(&dist_info_path), install_global_executable) {
            (Some(ep), _) => ep,
            (None, true) => eyre::bail!("{} contains no executables", distribution.name),
            (None, false) => vec![],
        };

        for entrypoint in entrypoints {
            let executables_path = virtpy.executables();
            let err = || eyre::eyre!("failed to install executable {}", entrypoint.name);
            let python_path = executables_path.join("python");
            entrypoint
                .generate_executable(&executables_path, &python_path)
                .wrap_err_with(err)?;

            if install_global_executable {
                entrypoint
                    .generate_executable(&proj_dirs.executables(), &python_path)
                    .wrap_err_with(err)?;
            }
        }
    }

    Ok(())
}

fn print_error_missing_file_in_record(dist_info: &str, missing_file: &Path) {
    println!(
        "couldn't find recorded file from {}: {}",
        dist_info,
        missing_file.display()
    )
}

fn remove_leading_parent_dirs(mut path: &Path) -> Result<&Path, &Path> {
    let mut anything_removed = false;
    while let Ok(stripped_path) = path.strip_prefix("..") {
        path = stripped_path;
        anything_removed = true;
    }
    if anything_removed {
        Ok(path)
    } else {
        Err(path)
    }
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

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Distribution {
    name: String,
    version: String,
    sha: String, // TODO: make this into a DependencyHash
}

impl Distribution {
    fn from_store_name(store_name: &str) -> Self {
        let mut it = store_name.split(",");
        let mut next = || it.next().unwrap().to_owned();
        let name = next();
        let version = next();
        let sha = next();
        assert!(it.next().is_none());

        Self { name, version, sha }
    }

    fn path(&self, project_dirs: &ProjectDirs) -> PathBuf {
        project_dirs
            .dist_infos()
            .join(dist_info_dirname(&self.name, &self.version, &self.sha))
    }

    fn record(&self, project_dirs: &ProjectDirs) -> PathBuf {
        self.path(project_dirs).join("RECORD")
    }

    fn records(
        &self,
        project_dirs: &ProjectDirs,
    ) -> csv::Result<impl Iterator<Item = csv::Result<InstalledFile>>> {
        records(&self.record(project_dirs))
    }
}

fn newly_installed_distributions(pip_log: &str) -> Vec<Distribution> {
    let mut installed_distribs = Vec::new();

    let install_url_pattern = Regex::new(
        r"Added ([\w_-]+)==(.*) from (https://[^\s]+)/([\w_]+)-[\w_\-\.]+#(sha256=[0-9a-fA-F]{64})",
    )
    .unwrap();

    for line in pip_log.lines() {
        if let Some(install_captures) = install_url_pattern.captures(line) {
            let get = |idx| install_captures.get(idx).unwrap().as_str().to_owned();
            // false name, may not have right case
            //let name = get(1);
            let version = get(2);
            //let url = get(3);
            let name = get(4);
            let sha = get(5);

            //installed_distribs.push((url, distribution, version));
            installed_distribs.push(Distribution { version, sha, name })
        } else if line.contains("Added ") {
            panic!("2: {}", line);
        }
    }

    installed_distribs
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_proj_dirs() -> ProjectDirs {
        let target = Path::new(env!("CARGO_MANIFEST_DIR"));
        let test_proj_dir = target.join("test_cache");
        let proj_dirs = ProjectDirs::from_path(test_proj_dir);
        proj_dirs.create_dirs().unwrap();
        proj_dirs
    }

    #[test]
    fn test_find_poetry() -> eyre::Result<()> {
        find_poetry().map(drop)
    }

    #[test]
    fn test_install_uninstall() -> eyre::Result<()> {
        let proj_dirs = test_proj_dirs();

        let options = Options { verbose: 3 };
        let force = true;
        let python = "3";

        let packages = [
            ("tuna", false),
            ("black", true),
            ("pylint", false),
            ("mypy", false),
            ("youtube-dl", false),
            ("vulture", false),
        ];

        for &(package, allow_prereleases) in &packages {
            install_executable_package(
                &proj_dirs,
                options,
                package,
                force,
                allow_prereleases,
                python,
            )?;
            delete_executable_virtpy(&proj_dirs, &package)?;
            assert_eq!(proj_dirs.executables().read_dir().unwrap().count(), 0);
        }
        Ok(())
    }

    #[test]
    fn test_pip_log_parsing() {
        let text = include_str!("../test_files/pip.log");
        let distribs = newly_installed_distributions(text);
        assert_eq!(
            distribs,
            &[
                Distribution {
                    name: "astroid".into(),
                    version: "2.4.2".into(),
                    sha: "sha256=bc58d83eb610252fd8de6363e39d4f1d0619c894b0ed24603b881c02e64c7386"
                        .into()
                },
                Distribution {
                    name: "isort".into(),
                    version: "4.3.21".into(),
                    sha: "sha256=6e811fcb295968434526407adb8796944f1988c5b65e8139058f2014cbe100fd"
                        .into()
                },
                Distribution {
                    name: "lazy_object_proxy".into(),
                    version: "1.4.3".into(),
                    sha: "sha256=a6ae12d08c0bf9909ce12385803a543bfe99b95fe01e752536a60af2b7797c62"
                        .into()
                },
                Distribution {
                    name: "mccabe".into(),
                    version: "0.6.1".into(),
                    sha: "sha256=ab8a6258860da4b6677da4bd2fe5dc2c659cff31b3ee4f7f5d64e79735b80d42"
                        .into()
                },
                Distribution {
                    name: "pylint".into(),
                    version: "2.5.3".into(),
                    sha: "sha256=d0ece7d223fe422088b0e8f13fa0a1e8eb745ebffcb8ed53d3e95394b6101a1c"
                        .into()
                },
                Distribution {
                    name: "six".into(),
                    version: "1.15.0".into(),
                    sha: "sha256=8b74bedcbbbaca38ff6d7491d76f2b06b3592611af620f8426e82dddb04a5ced"
                        .into()
                },
                Distribution {
                    name: "toml".into(),
                    version: "0.10.1".into(),
                    sha: "sha256=bda89d5935c2eac546d648028b9901107a595863cb36bae0c73ac804a9b4ce88"
                        .into()
                },
                Distribution {
                    name: "wrapt".into(),
                    version: "1.12.1".into(),
                    sha: "sha256=b62ffa81fb85f4332a4f609cab4ac40709470da05643a082ec1eb88e6d9b97d7"
                        .into()
                }
            ]
        );
    }

    #[test]
    fn test_records() {
        records("test_files/RECORD".as_ref())
            .unwrap()
            .map(Result::unwrap)
            .for_each(drop);
    }

    // #[test]
    // fn existing_deps_recognized_as_not_new_by_hash() {
    //     let proj_dir = proj_dir().unwrap();
    //     let data_dir = proj_dir.data_dir();

    //     let dist_infos = data_dir.join("dist-infos");
    //     let existing_deps = already_installed(&dist_infos).unwrap();

    //     let pseudo_reqs = existing_deps
    //         .into_iter()
    //         .map(|(hash, _)| python_requirements::Requirement {
    //             name: "".into(),
    //             available_hashes: vec![hash],
    //             version: "".into(),
    //             marker: None,
    //         })
    //         .collect::<Vec<_>>();
    //     let new_deps = new_dependencies(&pseudo_reqs, &dist_infos).unwrap();
    //     assert_eq!(&new_deps, &[]);
    // }

    #[test]
    fn read_entrypoints() {
        let entrypoints = entrypoints("test_files/entrypoints.dist-info".as_ref()).unwrap();
        assert_eq!(
            entrypoints,
            &[
                EntryPoint {
                    name: "dmypy".into(),
                    module: "mypy.dmypy.client".into(),
                    qualname: Some("console_entry".into())
                },
                EntryPoint {
                    name: "mypy".into(),
                    module: "mypy.__main__".into(),
                    qualname: Some("console_entry".into())
                },
                EntryPoint {
                    name: "stubgen".into(),
                    module: "mypy.stubgen".into(),
                    qualname: Some("main".into())
                },
                EntryPoint {
                    name: "stubtest".into(),
                    module: "mypy.stubtest".into(),
                    qualname: Some("main".into())
                },
            ]
        )
    }
}
