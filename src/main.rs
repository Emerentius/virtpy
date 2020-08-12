use directories::ProjectDirs;
use python_requirements::Requirement;
use regex::Regex;
use std::fmt::Write;
use std::{
    collections::HashMap,
    error::Error,
    path::{Path, PathBuf},
};
use structopt::StructOpt;

mod python_requirements;

#[derive(StructOpt)]
struct Opt {
    #[structopt(subcommand)] // Note that we mark a field as a subcommand
    cmd: Command,
}

#[derive(StructOpt)]
enum Command {
    /// Create a new virtpy environment
    New {
        path: Option<PathBuf>,
    },
    /// Add dependency to virtpy
    Add {
        requirements: PathBuf,
    },
    Install {
        package: String,
    },
    Uninstall {
        package: String,
    },
}

const DEFAULT_VIRTPY_PATH: &str = ".virtpy";
//const INSTALLED_DISTRIBUTIONS: &str = "installed_distributions.json";

// probably missing prereleases and such
// TODO: check official scheme
struct PythonVersion {
    major: i32,
    minor: i32,
    patch: i32,
}

fn python_version() -> Result<PythonVersion, Box<dyn Error>> {
    let mut path = PathBuf::from(DEFAULT_VIRTPY_PATH);
    path.push("bin");
    path.push("python3");
    let mut command = std::process::Command::new(path);
    command.arg("--version");
    let output = command.output();
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

#[derive(Clone, Hash, Debug, PartialEq, Eq)]
pub struct DependencyHash(String);

// The same distribution installed with different python versions
// might result in incompatible files.
// This implementation used a separate file in which the distribution sha could be mapped
// to a specific dist-info.
//
// fn already_installed(python_version: String) -> Result<HashSet<DependencyHash>, Box<dyn Error>> {
//     let proj_dir = proj_dir().unwrap();
//     let data_dir = proj_dir.data_dir();
//     // FIXME: this file may not exist

//     let data = std::fs::read_to_string(data_dir.join(INSTALLED_DISTRIBUTIONS))?;
//     let mut json_ = json::parse(&data)?;
//     let hashes = match &mut json_[&python_version] {
//         json::JsonValue::Array(values) => values,
//         _ => unreachable!(),
//     };
//     hashes
//         .into_iter()
//         .map(|val| val.take_string().map(crate::DependencyHash))
//         .collect::<Option<HashSet<_>>>()
//         .ok_or_else(|| {
//             format!(
//                 "{} contains non-hash values for {}",
//                 INSTALLED_DISTRIBUTIONS, python_version
//             )
//             .into()
//         })
// }

fn already_installed(
    // python_version: String,
    dist_infos: &Path,
) -> Result<HashMap<DependencyHash, PathBuf>, Box<dyn Error>> {
    std::fs::read_dir(dist_infos)?
        .map(|entry_res| {
            let dir_entry = entry_res?;
            let filename = dir_entry.file_name();
            let filename_str = filename.clone().into_string().unwrap();
            let hash = filename_str.split(",").last().unwrap();
            Ok((DependencyHash(hash.to_owned()), dist_infos.join(filename)))
        })
        .collect()
}

fn proj_dir() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "virtpy")
}

fn ensure_project_dir_exists() -> Result<(), Box<dyn Error>> {
    let proj_dirs = proj_dir().ok_or_else(|| "Couldn't create project directory")?;
    std::fs::create_dir_all(proj_dirs.data_dir())?;
    Ok(())
}

fn serialize_requirements_txt(reqs: &[Requirement]) -> String {
    let mut output = String::new();
    for req in reqs {
        let _ = write!(&mut output, "{}=={}", req.name, req.version);
        if let Some(sys_condition) = req.sys_condition.as_ref() {
            let _ = write!(&mut output, "{}", sys_condition);
        }
        let _ = writeln!(&mut output, " \\");
        let hashes = req
            .available_hashes
            .iter()
            .map(|hash| format!("    --hash={}", hash.0))
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

fn register_distribution_files(
    package_files_target: &Path,
    dist_infos_target: &Path,
    install_folder: &Path,
    distribution_name: &str,
    version: &str,
    sha: String,
) {
    let dist_info_foldername = format!("{}-{}.dist-info", distribution_name, version);
    let dist_info = install_folder.join(&dist_info_foldername);

    println!("Adding {} {} to central store.", distribution_name, version);
    // println!("record len: {}", record.len());
    for file in records(&dist_info.join("RECORD"))
        .unwrap()
        .map(Result::unwrap)
    {
        // Sanity check. We're not caching compiled code so pip is told not to compile python code.
        // If this folder exists, something went wrong.
        debug_assert!(file.path.iter().all(|part| part != "__pycache__"));

        let path = remove_leading_parent_dirs(&file.path).unwrap_or_else(std::convert::identity);
        debug_assert_ne!(file.hash, "");

        // TODO: use rename, if on same filesystem
        std::fs::copy(
            install_folder.join(path),
            package_files_target.join(file.hash),
        )
        .unwrap();
    }

    // println!("source exists: {}", dist_info.exists());
    let target = dist_infos_target.join(format!("{},{},{}", distribution_name, version, sha));

    if target.exists() {
        return;
    }
    // TODO: should try to move instead of copy, if possible
    copy_directory(&dist_info, &target);
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
    distribs: &[Requirement],
    package_files: &Path,
    dist_infos: &Path,
) -> Result<(), Box<dyn Error>> {
    std::fs::write(
        "__tmp_requirements.txt",
        serialize_requirements_txt(distribs),
    )?;
    let tmp_dir = tempdir::TempDir::new("")?;
    let output = std::process::Command::new("python3")
        .args(&[
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-compile",
            "-r",
            "__tmp_requirements.txt",
            "-t",
            tmp_dir.as_ref().as_os_str().to_str().unwrap(),
            "-v",
            "--no-cache-dir",
        ])
        .output()?;

    let pip_log = String::from_utf8(output.stdout)?;

    let new_distribs = newly_installed_distributions(pip_log);

    for distrib in new_distribs {
        register_distribution_files(
            &package_files,
            &dist_infos,
            tmp_dir.as_ref(),
            &distrib.name,
            &distrib.version,
            distrib.sha,
        );
    }
    Ok(())
}

fn new_dependencies(
    requirements: &[Requirement],
    dist_infos: &Path,
) -> Result<Vec<Requirement>, Box<dyn Error>> {
    let existing_deps = already_installed(&dist_infos)?;

    Ok(requirements
        .iter()
        .filter(|req| {
            !req.available_hashes
                .iter()
                .any(|hash| existing_deps.contains_key(hash))
        })
        .cloned()
        .collect::<Vec<_>>())
}

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: create on demand
    ensure_project_dir_exists()?;

    let opt = Opt::from_args();
    match opt.cmd {
        Command::Add { requirements } => {
            let python_version = python_version()?;
            let requirements = std::fs::read_to_string(requirements)?;
            let requirements = python_requirements::read_requirements_txt(&requirements);

            let proj_dir = proj_dir().unwrap();
            let data_dir = proj_dir.data_dir();

            let package_files = data_dir.join("package_files");
            let dist_infos = data_dir.join("dist-infos");
            std::fs::create_dir_all(&package_files)?;
            std::fs::create_dir_all(&dist_infos)?;

            let new_deps = new_dependencies(&requirements, &dist_infos)?;
            //install_and_register_distributions(&requirements, &package_files, &dist_infos)?;
            install_and_register_distributions(&new_deps, &package_files, &dist_infos)?;

            let mut requirements = requirements;
            requirements.retain(|req| {
                req.sys_condition
                    .as_ref()
                    .map_or(true, |cond| cond.matches_system())
            });
            link_requirements_into_virtpy(
                ".virtpy".as_ref(),
                &format!("python{}.{}", python_version.major, python_version.minor),
                &dist_infos,
                &package_files,
                &requirements,
            )?;
        }
        Command::New { path } => {
            let path = path.unwrap_or(DEFAULT_VIRTPY_PATH.into());
            let output = create_bare_venv(&path)?;

            if !output.status.success() {
                let error = std::str::from_utf8(&output.stderr).unwrap();
                println!("failed to create virtpy {}: {}", path.display(), error);
                std::process::exit(1);
            }
        }
        Command::Install { package } => {
            let proj_dir = proj_dir().unwrap();
            let data_dir = proj_dir.data_dir();
            let installations = data_dir.join("installations");
            std::fs::create_dir_all(&installations)?;

            let package_folder = installations.join(&format!("{}.virtpy", package));

            if package_folder.exists() {
                println!("package is already installed.");
                return Ok(());
            }

            let requirements = python_requirements::get_requirements(&package);

            let package_files = data_dir.join("package_files");
            let dist_infos = data_dir.join("dist-infos");
            create_bare_venv(&package_folder)?;

            let new_deps = new_dependencies(&requirements, &dist_infos)?;
            //install_and_register_distributions(&requirements, &package_files, &dist_infos)?;
            install_and_register_distributions(&new_deps, &package_files, &dist_infos)?;

            let python_version = python_version()?;
            link_requirements_into_virtpy(
                &package_folder,
                &format!("python{}.{}", python_version.major, python_version.minor),
                &dist_infos,
                &package_files,
                &requirements,
            )?;
        }
        Command::Uninstall { package } => {
            // FIXME: remove duplication of project dir code
            let proj_dir = proj_dir().unwrap();
            let data_dir = proj_dir.data_dir();
            let installations = data_dir.join("installations");

            std::fs::create_dir_all(&installations)?;

            let package_folder = installations.join(&format!("{}.virtpy", package));
            println!("{}", package_folder.display());
            assert!(!package_folder.exists() || package_folder.join("pyvenv.cfg").exists());
            std::fs::remove_dir_all(package_folder).or_else(ignore_target_doesnt_exist)?;
        }
    }

    Ok(())
}

fn create_bare_venv(path: &Path) -> std::io::Result<std::process::Output> {
    std::process::Command::new("python3")
        .args(&["-m", "venv", "--without-pip"])
        .arg(&path)
        .output()
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
    virtpy_dir: &Path,
    python_version: &str,
    dist_infos: &Path,
    package_files: &Path,
    requirements: &[Requirement],
) -> Result<(), Box<dyn Error>> {
    let site_packages = virtpy_dir.join(format!("lib/{}/site-packages", python_version));

    let existing_deps = already_installed(&dist_infos)?;
    for distribution in requirements {
        // find compatible hash
        // TODO: version compatibility check. Right now it just picks the first one
        //       that's already installed
        let dist_info_path = match distribution.available_hashes.iter().find_map(|hash| {
            // println!("searching installed dep, hash = {}", hash.0);
            //       installation uses <hash_type>=<value>
            //       requirements.txt <hash_type>:<value>
            // TODO: split hash type and hash into separate values
            let hash = DependencyHash(hash.0.replace(":", "="));
            existing_deps.get(&hash)
        }) {
            Some(path) => path,
            None => {
                println!(
                    "failed to find dist_info for distribution: {:?}",
                    distribution
                );
                continue;
            }
        };

        let dist_info_foldername =
            format!("{}-{}.dist-info", distribution.name, distribution.version);
        println!(
            "symlinking dist info, src exists = {}, path = {}",
            dist_info_path.exists(),
            dist_info_path.display()
        );
        let target = site_packages.join(dist_info_foldername);
        //std::fs::create_dir(&target);
        symlink_dir(dist_info_path, &target)
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
                    virtpy_dir.join(path)
                }
                Err(path) => {
                    let dest = site_packages.join(path);
                    let dir = dest.parent().unwrap();
                    std::fs::create_dir_all(&dir).unwrap();
                    dest
                }
            };

            symlink_file(&package_files.join(record.hash), &dest)
                .or_else(ignore_target_exists)
                .unwrap();
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

fn newly_installed_distributions(pip_log: String) -> Vec<Distribution> {
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
}
