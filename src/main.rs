use python_requirements::Requirement;
use regex::Regex;
use std::fmt::Write;
use std::{
    collections::HashMap,
    error::Error,
    fs::File,
    io::{BufReader, ErrorKind},
    path::{Path, PathBuf},
};
use structopt::StructOpt;

mod python_detection;
mod python_requirements;

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
        #[structopt(short, long, default_value = "python3")]
        python: String,
    },
    /// Add dependency to virtpy
    Add {
        requirements: PathBuf,
    },
    Install {
        package: String,
        #[structopt(short, long)]
        force: bool,
        #[structopt(long)]
        allow_prereleases: bool,
        #[structopt(short, long, default_value = "python3")]
        python: String,
    },
    Uninstall {
        package: String,
    },
    PoetryInstall {},
}

const DEFAULT_VIRTPY_PATH: &str = ".virtpy";
const INSTALLED_DISTRIBUTIONS: &str = "installed_distributions.json";

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

fn python_version(python_path: &Path) -> Result<PythonVersion, Box<dyn Error>> {
    let output = std::process::Command::new(python_path)
        .arg("--version")
        .output();
    let version = String::from_utf8(output.unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let captures = regex::Regex::new(r"Python (\d+)\.(\d+)\.(\d+)")
        .unwrap()
        .captures(&version)
        .unwrap();

    let get_num = |idx: usize| captures[idx].parse::<i32>().unwrap();
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
    fn load(proj_dirs: &ProjectDirs) -> Result<Self, Box<dyn Error>> {
        let file = match File::open(proj_dirs.installed_distributions()) {
            Ok(f) => f,
            Err(err) if err.kind() == ErrorKind::NotFound => {
                return Ok(StoredDistributions(HashMap::new()));
            }
            Err(err) => return Err(err.into()),
        };
        let reader = BufReader::new(file);
        Ok(serde_json::from_reader(reader)?)
    }

    fn save(&self, proj_dirs: &ProjectDirs) -> Result<(), Box<dyn Error>> {
        let file = File::create(proj_dirs.installed_distributions())?;
        // NOTE: does this need a BufWriter?
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
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
            std::fs::create_dir(target_path).unwrap();
        } else {
            std::fs::copy(path, target_path).unwrap();
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

    fn executable_code(&self, python_path: &Path) -> String {
        format!(
            r"#!{}
# -*- coding: utf-8 -*-
import re
import sys
from {} import {qualname}
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit({qualname}())
",
            python_path.display(),
            self.module,
            qualname = self.qualname.clone().unwrap()
        )
    }

    fn generate_executable(&self, dest: &Path, python_path: &Path) {
        let content = self.executable_code(&python_path);
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(target_family = "unix")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o744);
        }

        let dest = match dest.is_dir() {
            true => dest.join(&self.name),
            false => dest.to_owned(),
        };

        let mut f = opts.open(dest).unwrap();
        use std::io::Write;
        f.write_all(content.as_bytes()).unwrap();
    }
}

fn entrypoints(dist_info: &Path) -> Vec<EntryPoint> {
    let ini = dist_info.join("entry_points.txt");
    let ini = ini::Ini::load_from_file(ini);

    match ini {
        Err(ini::ini::Error::Io(err)) if err.kind() == std::io::ErrorKind::NotFound => {
            return vec![]
        }
        _ => (),
    };
    let ini = ini.unwrap();

    ini.section(Some("console_scripts"))
        .map_or(vec![], |console_scripts| {
            console_scripts
                .iter()
                .map(|(key, val)| EntryPoint::new(key, val))
                .collect()
        })
}

fn register_distribution_files(
    proj_dirs: &ProjectDirs,
    install_folder: &Path,
    distribution_name: &str,
    version: &str,
    sha: String,
    stored_distributions: &mut HashMap<DependencyHash, PathBuf>,
    options: crate::Options,
) {
    let dist_info_foldername = format!("{}-{}.dist-info", distribution_name, version);
    let src_dist_info = install_folder.join(&dist_info_foldername);

    let dst_dist_info_dirname = format!("{},{},{}", distribution_name, version, sha);
    let dst_dist_info = proj_dirs.dist_infos().join(&dst_dist_info_dirname);

    if dst_dist_info.exists() {
        // add it here, because it may have been installed by a different
        // python version. In that case, the current python version's list
        // may be missing this distribution.
        stored_distributions.insert(DependencyHash(sha), PathBuf::from(dst_dist_info_dirname));
        return;
    }
    if options.verbose >= 1 {
        println!("Adding {} {} to central store.", distribution_name, version);
    }

    for file in records(&src_dist_info.join("RECORD"))
        .unwrap()
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
        let res = std::fs::copy(src, dest);
        match &res {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => println!(
                "couldn't find recorded file from {}: {}",
                dist_info_foldername,
                file.path.display()
            ),
            _ => {
                res.unwrap();
            }
        };
    }

    // TODO: should try to move instead of copy, if possible
    copy_directory(&src_dist_info, &dst_dist_info);
    stored_distributions.insert(DependencyHash(sha), PathBuf::from(dst_dist_info_dirname));
}

#[derive(Debug, serde::Deserialize)]
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
) -> Result<(), Box<dyn Error>> {
    if options.verbose >= 1 {
        println!("Adding {} new distributions", distribs.len());
    }
    if distribs.is_empty() {
        return Ok(());
    }

    let tmp_dir = tempdir::TempDir::new("virtpy")?;
    let tmp_requirements = tmp_dir.as_ref().join("__tmp_requirements.txt");
    let reqs = serialize_requirements_txt(distribs);
    std::fs::write(&tmp_requirements, reqs)?;
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

            let _ = std::fs::write(proj_dirs.data().join("pip.log"), pip_log);
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
            distrib.sha,
            stored_distributions,
            options,
        );
    }

    all_stored_distributions.save(proj_dirs)?;

    Ok(())
}

fn new_dependencies(
    requirements: &[Requirement],
    proj_dirs: &ProjectDirs,
    python_version: PythonVersion,
) -> Result<Vec<Requirement>, Box<dyn Error>> {
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

fn python_path(virtpy: &Path) -> PathBuf {
    let bin_dir = if cfg!(target_os = "windows") {
        "Scripts"
    } else {
        "bin"
    };
    virtpy.join(bin_dir).join("python")
}

// toplevel options
#[derive(Copy, Clone)]
struct Options {
    verbose: u8,
}

struct ProjectDirs(directories::ProjectDirs);

impl ProjectDirs {
    fn new() -> Option<Self> {
        directories::ProjectDirs::from("", "", "virtpy").map(Self)
    }

    fn create_dirs(&self) -> std::io::Result<()> {
        use std::fs;
        fs::create_dir_all(self.0.data_dir())?;
        for path in &[
            self.installations(),
            self.dist_infos(),
            self.package_files(),
            self.executables(),
        ] {
            fs::create_dir(path).or_else(ignore_target_exists)?;
        }
        Ok(())
    }

    fn data(&self) -> &Path {
        self.0.data_dir()
    }

    fn installations(&self) -> PathBuf {
        self.data().join("installations")
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

    fn installed_distributions(&self) -> PathBuf {
        self.data().join(INSTALLED_DISTRIBUTIONS)
    }

    fn package_folder(&self, package: &str) -> PathBuf {
        self.installations().join(&format!("{}.virtpy", package))
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let proj_dirs = ProjectDirs::new().unwrap();
    // TODO: create on demand
    proj_dirs.create_dirs()?;

    let opt = Opt::from_args();
    let options = Options {
        verbose: opt.verbose,
    };
    match opt.cmd {
        Command::Add { requirements } => {
            let virtpy_path = DEFAULT_VIRTPY_PATH.as_ref();
            let python_version = python_version(&python_path(virtpy_path))?;
            let requirements = std::fs::read_to_string(requirements)?;
            let requirements = python_requirements::read_requirements_txt(&requirements);

            virtpy_add_dependencies(
                &proj_dirs,
                virtpy_path,
                requirements,
                python_version,
                options,
            )?;
        }
        Command::New { python } => {
            let path = PathBuf::from(DEFAULT_VIRTPY_PATH);
            let python_path = python_detection::detect(&python)
                .ok_or(format!("Couldn't find python executable '{}'", python))?;
            let output = create_bare_venv(&python_path, &path)?;

            if !output.status.success() {
                let error = std::str::from_utf8(&output.stderr).unwrap();
                println!("failed to create virtpy {}: {}", path.display(), error);
                std::process::exit(1);
            }
        }
        Command::Install {
            package,
            force,
            allow_prereleases,
            python,
        } => {
            let package_folder = proj_dirs.package_folder(&package);

            let python_path = python_detection::detect(&python)
                .ok_or(format!("Couldn't find python executable '{}'", python))?;

            if package_folder.exists() {
                if force {
                    delete_executable_virtpy(&package_folder)?;
                } else {
                    println!("package is already installed.");
                    return Ok(());
                }
            }

            check_poetry_available()?;

            let requirements = python_requirements::get_requirements(&package, allow_prereleases);

            create_bare_venv(&python_path, &package_folder)?;

            // if anything goes wrong, try to delete the incomplete installation
            let venv_deleter = scopeguard::guard((), |_| {
                let _ = delete_executable_virtpy(&package_folder);
            });

            let python_version = python_version(&python_path)?;

            virtpy_add_dependencies(
                &proj_dirs,
                &package_folder,
                requirements,
                python_version,
                options,
            )?;

            // if everything succeeds, keep the venv
            std::mem::forget(venv_deleter);
        }
        Command::Uninstall { package } => {
            delete_executable_virtpy(&proj_dirs.package_folder(&package))?;
        }
        Command::PoetryInstall {} => {
            let virtpy_path = DEFAULT_VIRTPY_PATH.as_ref();
            let python_version = python_version(&python_path(virtpy_path))?;
            let requirements = python_requirements::poetry_get_requirements(Path::new("."));
            virtpy_add_dependencies(
                &proj_dirs,
                virtpy_path,
                requirements,
                python_version,
                options,
            )?;
        }
    }

    Ok(())
}

fn virtpy_add_dependencies(
    proj_dirs: &ProjectDirs,
    virtpy_path: &Path,
    requirements: Vec<Requirement>,
    python_version: PythonVersion,
    options: Options,
) -> Result<(), Box<dyn Error>> {
    let new_deps = new_dependencies(&requirements, proj_dirs, python_version)?;

    // The virtpy doesn't contain pip so get the appropriate global python
    let python_path = global_python(virtpy_path);

    //install_and_register_distributions(&requirements, &package_files, &dist_infos)?;
    install_and_register_distributions(
        &python_path,
        proj_dirs,
        &new_deps,
        python_version,
        options,
    )?;

    link_requirements_into_virtpy(
        proj_dirs,
        virtpy_path,
        python_version,
        requirements,
        options,
        None,
    )
}

fn global_python(virtpy_path: &Path) -> PathBuf {
    // FIXME: On windows, the virtpy python is a copy, so there's no symlink to resolve.
    //        We need to take the version and then do a search for the real python.
    python_path(virtpy_path).canonicalize().unwrap()
}

fn delete_executable_virtpy(package_folder: &Path) -> std::io::Result<()> {
    println!("removing {}", package_folder.display());
    assert!(!package_folder.exists() || package_folder.join("pyvenv.cfg").exists());
    assert_eq!(package_folder.extension(), Some("virtpy".as_ref()));
    std::fs::remove_dir_all(package_folder).or_else(ignore_target_doesnt_exist)
}

fn create_bare_venv(python_path: &Path, path: &Path) -> std::io::Result<std::process::Output> {
    std::process::Command::new(python_path)
        .args(&["-m", "venv", "--without-pip"])
        .arg(&path)
        .output()
}

fn check_poetry_available() -> Result<(), Box<dyn Error>> {
    // TODO: maybe check error code as well and pass the stderr msg up
    std::process::Command::new("poetry")
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        //.output()
        .map_err(|err| -> Box<dyn Error> {
            if err.kind() == std::io::ErrorKind::NotFound {
                "this command requires poetry to be installed and on the PATH. (https://github.com/python-poetry/poetry)".into()
            } else {
                Box::new(err).into()
            }
        })
        .map(drop)
}

fn symlink_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::os::unix::fs::symlink(from, to)
    }

    #[cfg(target_os = "windows")]
    {
        std::os::windows::fs::symlink_dir(from, to)
    }
}

fn symlink_file(from: &Path, to: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::os::unix::fs::symlink(from, to)
    }

    #[cfg(target_os = "windows")]
    {
        std::os::windows::fs::symlink_file(from, to)
    }
}

fn link_requirements_into_virtpy(
    proj_dirs: &ProjectDirs,
    virtpy_dir: &Path,
    python_version: PythonVersion,
    mut requirements: Vec<Requirement>,
    options: Options,
    additional_executables_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    let site_packages = virtpy_dir.join(format!(
        "lib/python{}/site-packages",
        python_version.as_string_without_patch()
    ));

    requirements.retain(|req| {
        req.marker
            .as_ref()
            .map_or(true, |cond| cond.matches_system())
    });
    let requirements = requirements;

    let stored_distributions = StoredDistributions::load(proj_dirs)?;
    let existing_deps = stored_distributions
        .0
        .get(&python_version.as_string_without_patch())
        .cloned()
        .unwrap_or_default();
    for distribution in requirements {
        // find compatible hash
        // TODO: version compatibility check. Right now it just picks the first one
        //       that's already installed
        let dist_info_path = match distribution.available_hashes.iter().find_map(|hash| {
            // println!("searching installed dep, hash = {}", hash.0);
            //       installation uses <hash_type>=<value>
            //       requirements.txt <hash_type>:<value>
            existing_deps.get(&hash)
        }) {
            Some(path) => proj_dirs.dist_infos().join(path),
            None => {
                return Err(format!(
                    "failed to find dist_info for distribution: {:?}",
                    distribution
                )
                .into());
                // println!(
                //     "failed to find dist_info for distribution: {:?}",
                //     distribution
                // );
                // continue;
            }
        };

        let dist_info_foldername =
            format!("{}-{}.dist-info", distribution.name, distribution.version);
        let target = site_packages.join(dist_info_foldername);
        if options.verbose >= 1 {
            println!(
                "symlinking dist info from {} to {}",
                dist_info_path.display(),
                target.display()
            );
        }
        //std::fs::create_dir(&target);
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
                    assert!(toplevel_dirs.iter().any(|dir| path.starts_with(dir)));

                    // executables need to be generated on demand
                    if is_path_of_executable(path) {
                        continue;
                    }

                    virtpy_dir.join(path)
                }
                Err(path) => {
                    let dest = site_packages.join(path);
                    let dir = dest.parent().unwrap();
                    std::fs::create_dir_all(&dir).unwrap();
                    dest
                }
            };

            symlink_file(&proj_dirs.package_files().join(record.hash), &dest)
                .or_else(ignore_target_exists)
                .unwrap();
        }

        for entrypoint in entrypoints(&dist_info_path) {
            let executables_path = virtpy_dir.join(match cfg!(target_os = "windows") {
                true => "Scripts",
                false => "bin",
            });
            let python_path = executables_path.join("python");
            entrypoint.generate_executable(&executables_path, &python_path);

            // FIXME: this will silently overwrite old files with the same name
            if let Some(additional_path) = additional_executables_path {
                entrypoint.generate_executable(&additional_path, &python_path);
            }
        }
    }

    Ok(())
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
    if err.kind() == std::io::ErrorKind::NotFound {
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

#[derive(Debug)]
struct Distribution {
    name: String,
    version: String,
    sha: String,
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

/*
#[test]
fn test_pip_log_parsing() {
    let text = include_str!("../output.txt");
    let distribs = newly_installed_distributions(text.to_owned());
    panic!("{:?}", distribs);
}
*/

#[cfg(test)]
mod test {
    use super::*;

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
        let entrypoints = entrypoints("test_files/entrypoints.dist-info".as_ref());
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
