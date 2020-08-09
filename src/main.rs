use directories::ProjectDirs;
use python_requirements::Requirement;
use regex::Regex;
use std::fmt::Write;
use std::{
    collections::HashSet,
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
    New { path: Option<PathBuf> },
    /// Add dependency to virtpy
    Add { requirements: PathBuf },
}

const DEFAULT_VIRTPY_PATH: &str = ".virtpy";
const INSTALLED_DISTRIBUTIONS: &str = "installed_distributions.json";

fn python_version() -> Result<String, Box<dyn Error>> {
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
    Ok(version)
}

#[derive(Clone, Hash, Debug, PartialEq, Eq)]
pub struct DependencyHash(String);

fn already_installed(python_version: String) -> Result<HashSet<DependencyHash>, Box<dyn Error>> {
    let proj_dir = proj_dir().unwrap();
    let data_dir = proj_dir.data_dir();
    // FIXME: this file may not exist

    let data = std::fs::read_to_string(data_dir.join(INSTALLED_DISTRIBUTIONS))?;
    let mut json_ = json::parse(&data)?;
    let hashes = match &mut json_[&python_version] {
        json::JsonValue::Array(values) => values,
        _ => unreachable!(),
    };
    hashes
        .into_iter()
        .map(|val| val.take_string().map(crate::DependencyHash))
        .collect::<Option<HashSet<_>>>()
        .ok_or_else(|| {
            format!(
                "{} contains non-hash values for {}",
                INSTALLED_DISTRIBUTIONS, python_version
            )
            .into()
        })
}

fn proj_dir() -> Option<ProjectDirs> {
    ProjectDirs::from("", "", "virtpy")
}

fn ensure_project_dir_exists() -> Result<(), Box<dyn Error>> {
    let proj_dirs = proj_dir().ok_or_else(|| "Couldn't create project directory")?;
    std::fs::create_dir_all(proj_dirs.data_dir())?;
    Ok(())
}

fn serialize_requirements_txt(reqs: Vec<python_requirements::Requirement>) -> String {
    let mut output = String::new();
    for req in reqs {
        let _ = write!(&mut output, "{}=={}", req.name, req.version);
        if req.sys_condition != "" {
            let _ = write!(&mut output, "{}", req.sys_condition);
        }
        let _ = writeln!(&mut output, " \\");
        let hashes = req
            .available_hashes
            .into_iter()
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
    //let package_files = data_dir.join("package_files");
    let dist_info_foldername = format!("{}-{}.dist-info", distribution_name, version);
    let dist_info = install_folder.join(&dist_info_foldername);

    println!("dist-info: {}", dist_info.display());

    let record = std::fs::read_to_string(dist_info.join("RECORD")).unwrap();

    println!("{}", distribution_name);
    println!("record len: {}", record.len());
    for line in record
        .lines()
        .filter(|line| !line.starts_with(&dist_info_foldername))
    {
        println!("{}", line);
        // Sanity check. We're not caching compiled code so pip is told not to compile python code.
        // If this folder exists, something went wrong.
        debug_assert!(!line.contains("__pycache__"));

        // when pip is told to install distributions to target folder
        // with -t flag, the bin folder will be right next to the packages.
        // The path in RECORD is the path where it would be if installed in
        // a regular environment, so it contains leading ".."s that need to
        // be stripped.

        let mut components = line.split(",");
        // assuming paths in RECORD use forward slashes even on windows
        // TODO: verify
        let path = components.next().unwrap().trim_start_matches("../");
        let path = Path::new(path);
        let hash = components.next().unwrap();
        debug_assert_ne!(hash, "");
        // TODO: docs say rename fails if from and to are on different filesystems.
        std::fs::copy(install_folder.join(path), package_files_target.join(hash)).unwrap();
    }

    println!("source exists: {}", dist_info.exists());
    let target = dist_infos_target.join(format!("{},{},{}", distribution_name, version, sha));

    println!(
        "target: (exists = {}) {}",
        target.exists(),
        target.display()
    );

    // fs_extra will otherwise append the source dir name
    if target.exists() {
        return;
    }
    // TODO: should try to move instead of copy, if possible
    copy_directory(&dist_info, &target);
}

fn install_and_register_distributions(distribs: Vec<Requirement>) -> Result<(), Box<dyn Error>> {
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

    let proj_dir = proj_dir().unwrap();
    let data_dir = proj_dir.data_dir();

    let package_files = data_dir.join("package_files");
    let dist_infos = data_dir.join("dist-infos");
    std::fs::create_dir_all(&package_files)?;
    std::fs::create_dir_all(&dist_infos)?;

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

fn main() -> Result<(), Box<dyn Error>> {
    // TODO: create on demand
    ensure_project_dir_exists()?;

    let opt = Opt::from_args();
    match opt.cmd {
        Command::Add { requirements } => {
            let python_version = python_version()?;
            let requirements = std::fs::read_to_string(requirements)?;
            let requirements = python_requirements::read_requirements_txt(requirements);

            let existing_deps = already_installed(python_version)?;

            let new_deps = requirements
                .clone()
                .into_iter()
                .filter(|req| {
                    req.available_hashes
                        .iter()
                        .any(|hash| existing_deps.contains(hash))
                })
                .collect::<Vec<_>>();

            install_and_register_distributions(requirements)?;
        }
        Command::New { path } => {
            let path = path.unwrap_or(DEFAULT_VIRTPY_PATH.into());
            let path = path.as_os_str().to_string_lossy();
            let mut command = std::process::Command::new("python3");
            let output = command
                .args(&["-m", "venv", "--without-pip", &path])
                .output()?;

            if !output.status.success() {
                let error = std::str::from_utf8(&output.stderr).unwrap();
                println!("failed to create virtpy {}: {}", path, error);
                std::process::exit(1);
            }
        }
    }

    Ok(())
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
