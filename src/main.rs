use camino::{Utf8Path, Utf8PathBuf};
use eyre::bail;
use eyre::{ensure, eyre, WrapErr};
use fs_err::File;
use itertools::Itertools;
use python_requirements::Requirement;
use python_wheel::{RecordEntry, WheelRecord};
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fmt::Write;
use std::io::Seek;
use std::{collections::HashMap, io::BufReader, path::Path as StdPath};
use structopt::StructOpt;

mod internal_store;
mod python_detection;
mod python_requirements;
mod python_wheel;

use fs_err::PathExt;

#[cfg(unix)]
use fs_err::os::unix::fs::symlink as symlink_dir;
#[cfg(windows)]
use fs_err::os::windows::fs::symlink_dir;

#[cfg(unix)]
use fs_err::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
use fs_err::os::windows::fs::symlink_file;

// defining it as an alias allows rust-analyzer to suggest importing it
// unlike a `use foo as bar` import.
type EResult<T> = eyre::Result<T>;
type Path = Utf8Path;
type PathBuf = Utf8PathBuf;

#[derive(StructOpt)]
#[structopt(global_setting(structopt::clap::AppSettings::ColoredHelp))]
struct Opt {
    #[structopt(subcommand)] // Note that we mark a field as a subcommand
    cmd: Command,
    #[structopt(short, parse(from_occurrences))]
    verbose: u8,
    #[structopt(long, hidden = true)]
    project_dir: Option<PathBuf>,
}

#[derive(StructOpt)]
enum Command {
    /// Create a new virtpy environment
    New {
        path: Option<PathBuf>,
        /// The python to use. Either a path or an indicator of the form `python3.7` or `3.7`
        #[structopt(short, long, default_value = "3")]
        python: String,
        #[structopt(long)]
        without_pip_shim: bool,
    },
    /// Add dependency to virtpy
    Add {
        requirements: PathBuf,
        #[structopt(long)]
        virtpy_path: Option<PathBuf>,
    },
    /// Remove dependency from virtpy
    Remove {
        distributions: Vec<String>,
        #[structopt(long)]
        virtpy_path: Option<PathBuf>,
    },
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
    Uninstall {
        package: Vec<String>,
    },
    /// Print paths where various files are stored
    Path(PathCmd),
    InternalStore(InternalStoreCmd),
    InternalUseOnly(InternalUseOnly),
}

#[derive(StructOpt)]
enum InternalStoreCmd {
    /// Find virtpys that have been moved or deleted and unneeded files in the central store.
    Gc {
        /// Delete unnecessary files
        #[structopt(long)]
        remove: bool,
    },
    /// Show how much storage is used
    Stats {
        /// Show sizes in bytes
        #[structopt(long, short)]
        bytes: bool,
        /// Use binary prefixes instead of SI.
        ///
        /// This uses powers of 1024 instead of 1000 and will print the accompanying symbol (e.g. 1 KiB for 1024 bytes).
        /// Has no effect if `--bytes` is passed.
        #[structopt(long)]
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

#[derive(StructOpt)]
enum InternalUseOnly {
    AddFromFile { virtpy: PathBuf, file: PathBuf },
}

#[derive(StructOpt)]
enum PathCmd {
    /// Directory where executables are placed by `virtpy install`
    Bin,
    /// Alias for `bin`
    Executables,
}

const DEFAULT_VIRTPY_PATH: &str = ".venv";
const INSTALLED_DISTRIBUTIONS: &str = "installed_distributions.json";
const CENTRAL_METADATA: &str = "virtpy_central_metadata";
const LINK_METADATA: &str = "virtpy_link_metadata";

const INVALID_UTF8_PATH: &str = "path is not valid utf8";

// name of file we add to .dist-info dir containing the distribution's hash
const DIST_HASH_FILE: &str = "DISTRIBUTION_HASH";

fn check_output(cmd: &mut std::process::Command) -> EResult<String> {
    String::from_utf8(_check_output(cmd)?)
        .wrap_err_with(|| eyre!("output isn't valid utf8 for {:?}", cmd))
}

fn check_status(cmd: &mut std::process::Command) -> EResult<()> {
    _check_output(cmd).map(drop)
}

fn _check_output(cmd: &mut std::process::Command) -> EResult<Vec<u8>> {
    let output = cmd.output()?;
    ensure!(output.status.success(), {
        let error = String::from_utf8_lossy(&output.stderr);
        eyre!("command failed\n    {:?}:\n{}", cmd, error)
    });
    Ok(output.stdout)
}

// probably missing prereleases and such
// TODO: check official scheme
#[derive(Copy, Clone)]
pub struct PythonVersion {
    // TODO: make these u32
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

fn python_version(python_path: &Path) -> EResult<PythonVersion> {
    let output = check_output(std::process::Command::new(python_path).arg("--version"))
        .wrap_err_with(|| eyre!("couldn't get python version of `{}`", python_path))?;
    let version = output.trim().to_owned();
    let (_, major, minor, patch) =
        lazy_regex::regex_captures!(r"Python (\d+)\.(\d+)\.(\d+)", &version)
            .ok_or_else(|| eyre!("failed to read python version from {:?}", version))?;

    let parse_num = |num: &str| {
        num.parse::<i32>()
            .wrap_err_with(|| eyre!("failed to parse number: \"{:?}\"", num))
    };
    Ok(PythonVersion {
        major: parse_num(major)?,
        minor: parse_num(minor)?,
        patch: parse_num(patch)?,
    })
}

// The base16 encoded hash of a distribution file, in most cases of a wheel file
// but it could also be of a tar.gz file, for example.
// Has the form "sha256=[0-9a-fA-F]{64}".
#[derive(
    Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct DistributionHash(String);

// The base64 encoded hash of a file in a wheel.
// has the form "sha256=${base64_encoded_string}"

#[derive(
    Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[must_use]
pub struct FileHash(String);

impl AsRef<Path> for FileHash {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl DistributionHash {
    fn from_file(path: &Path) -> Self {
        Self(format!("sha256={}", hash_of_file_sha256_base16(path)))
    }
}

impl FileHash {
    // TODO: use when checking file hashes in RECORD to be correct
    #[allow(unused)]
    fn from_file(path: &Path) -> Self {
        Self::from_hash(hash_of_file_sha256_base64(path))
    }

    // files in the repository are named after their hash, so we can just use the filename
    fn from_filename(path: &Path) -> Self {
        Self(path.file_name().unwrap().to_owned())
    }

    fn from_reader(reader: impl std::io::Read) -> Self {
        Self::from_hash(hash_of_reader_sha256_base64(reader))
    }

    fn from_hash(hash: String) -> Self {
        Self(format!("sha256={}", hash))
    }
}

impl std::fmt::Display for DistributionHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize, Clone)]
struct StoredDistribution {
    distribution: Distribution,
    installed_via: StoredDistributionType,
}

#[derive(Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize, Clone)]
enum StoredDistributionType {
    // A distribution that was installed via pip into a directory, then moved into the repository.
    FromPip,
    // A distribution that was added via its wheel file by our own unpacking code.
    // These contain fewer errors and allow for correctly dealing with the wheel's data directory,
    // in particular its scripts.
    FromWheel,
}

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
#[derive(Debug)]
struct StoredDistributions(_StoredDistributions, FileLockGuard);

type _StoredDistributions = HashMap<String, HashMap<DistributionHash, StoredDistribution>>;

impl PartialEq for StoredDistributions {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl Eq for StoredDistributions {}

impl StoredDistribution {
    fn dist_info_file(&self, proj_dirs: &ProjectDirs, file: &str) -> Option<PathBuf> {
        match self.installed_via {
            StoredDistributionType::FromPip => {
                let file = proj_dirs
                    .dist_infos()
                    .join(self.distribution.as_csv())
                    .join(file);
                file.exists().then(|| file)
            }
            StoredDistributionType::FromWheel => {
                let record_path = proj_dirs
                    .records()
                    .join(self.distribution.as_csv())
                    .join("RECORD");
                if file == "RECORD" {
                    return Some(record_path);
                }

                // TODO: optimize. kinda wasteful to keep rereading this on every call
                let path_in_record = PathBuf::from(self.distribution.dist_info_name()).join(file);
                let record = WheelRecord::from_file(record_path).unwrap();
                record
                    .files
                    .into_iter()
                    .find(|entry| entry.path == path_in_record)
                    .map(|entry| proj_dirs.package_file(&entry.hash))
            }
        }
    }

    fn entrypoints(&self, proj_dirs: &ProjectDirs) -> Option<Vec<EntryPoint>> {
        _entrypoints(&self.dist_info_file(proj_dirs, "entry_points.txt")?)
    }

    // Returns the directory where the RECORD of this distribution is stored.
    // For pip-installed distributions, this is the entire dist-info directory.
    // For direct-installed distributions, it's a directory containing only the unmodified RECORD
    // from the wheel archive.
    //
    // Deleting this directory means removing all information needed to use the distribution.
    // Running a garbage collection afterwards will delete all of the distribution's files
    // that are not shared with other distributions.
    // It must also be removed from StoredDistributions.
    fn path(&self, project_dirs: &ProjectDirs) -> PathBuf {
        let base = match self.installed_via {
            StoredDistributionType::FromPip => project_dirs.dist_infos(),
            StoredDistributionType::FromWheel => project_dirs.records(),
        };
        base.join(self.distribution.as_csv())
    }

    fn records(
        &self,
        project_dirs: &ProjectDirs,
    ) -> EResult<Box<dyn Iterator<Item = EResult<RecordEntry>>>> {
        let record = self.dist_info_file(project_dirs, "RECORD").unwrap();
        Ok(match self.installed_via {
            StoredDistributionType::FromPip => Box::new(records(&record)?.map(|rec| Ok(rec?))),
            StoredDistributionType::FromWheel => {
                Box::new(WheelRecord::from_file(&record)?.files.into_iter().map(Ok))
            }
        })
    }

    // The executables of this distribution that can be added to the global install dir.
    // For wheel installs this is both entrypoints and scripts from the data dir, but
    // for the legacy pip installed distributions it is just the entrypoints.
    fn executable_names(&self, proj_dirs: &ProjectDirs) -> eyre::Result<HashSet<String>> {
        let entrypoint_exes = self
            .entrypoints(proj_dirs)
            .unwrap_or_default()
            .into_iter()
            .map(|ep| ep.name)
            .collect::<HashSet<_>>();
        let mut exes = entrypoint_exes.clone();
        if self.installed_via == StoredDistributionType::FromWheel {
            let record = WheelRecord::from_file(self.dist_info_file(proj_dirs, "RECORD").unwrap())?;
            let mut data_exes = record.files;
            let script_path = PathBuf::from(self.distribution.data_dir_name()).join("scripts");
            data_exes.retain(|entry| entry.path.starts_with(&script_path));

            let data_exes = data_exes
                .into_iter()
                .map(|entry| entry.path.file_name().unwrap().to_owned())
                .collect::<HashSet<_>>();

            let duplicates = entrypoint_exes
                .intersection(&data_exes)
                .cloned()
                .collect::<Vec<_>>();
            // TODO: actually, this could happen even within entrypoints only.
            ensure!(
                duplicates.is_empty(),
                "distribution {} contains executables with duplicate names: {}",
                self.distribution.name_and_version(),
                duplicates.join(", ")
            );

            exes.extend(data_exes);
        }
        Ok(exes)
    }
}

impl StoredDistributions {
    fn try_load_old(reader: impl std::io::Read) -> Option<_StoredDistributions> {
        let stored_distribs = serde_json::from_reader::<
            _,
            HashMap<String, HashMap<DistributionHash, String>>,
        >(reader)
        .ok()?;

        let mut new_format_stored_distribs =
            HashMap::<String, HashMap<DistributionHash, StoredDistribution>>::new();

        for (python_version, inner) in stored_distribs {
            let entry = new_format_stored_distribs
                .entry(python_version)
                .or_default();
            for (key_hash, name_and_version_and_hash) in inner {
                let distribution = Distribution::from_store_name(&name_and_version_and_hash);
                debug_assert_eq!(key_hash, distribution.sha);

                entry.insert(
                    key_hash,
                    StoredDistribution {
                        distribution,
                        installed_via: StoredDistributionType::FromPip,
                    },
                );
            }
        }
        Some(new_format_stored_distribs)
    }

    fn load(proj_dirs: &ProjectDirs) -> EResult<Self> {
        Self::load_from(proj_dirs.installed_distributions_log())
    }

    fn load_from(path: impl AsRef<Path>) -> EResult<Self> {
        Self::_load_from(path.as_ref())
    }

    fn _load_from(path: &Path) -> EResult<Self> {
        let file = fs_err::OpenOptions::new()
            .create(true)
            .read(true)
            // we're actually only reading, but when create(true) is used,
            // the file must be set to write or append
            .write(true)
            .open(path)
            .wrap_err("failed to open stored distributions log")?;

        let mut lock = lock_file(file)?;
        if lock.metadata().unwrap().len() == 0 {
            // if it's empty, then deserializing it doesn't work
            // TODO: check if deserializing into Option<T> will allow deserializing from empty
            return Ok(StoredDistributions(HashMap::new(), lock));
        }

        if let Some(stored_distribs) = Self::try_load_old(BufReader::new(&*lock)) {
            return Ok(Self(stored_distribs, lock));
        }

        lock.seek(std::io::SeekFrom::Start(0))
            .wrap_err("failed to seek to 0")?;

        let distribs = serde_json::from_reader(BufReader::new(&*lock))
            .wrap_err("couldn't load stored distributions")?;
        Ok(Self(distribs, lock))
    }

    fn save(&self) -> EResult<()> {
        self._save().wrap_err("failed to save stored distributions")
    }

    fn _save(&self) -> EResult<()> {
        let mut file = &self.1.file;
        // Truncate file, then write to it.
        file.seek(std::io::SeekFrom::Start(0))?;
        file.set_len(0)?;
        serde_json::to_writer_pretty(file, &self.0)?;
        Ok(())
    }
}

// TODO: Find a good crate for this that also offers locking with timeouts and
//       a lock that contains the pid of the process holding it, so it can be
//       detected if the locking process is dead.
fn lock_file(file: fs_err::File) -> EResult<FileLockGuard> {
    use fs2::FileExt;
    file.file().lock_exclusive()?;
    Ok(FileLockGuard { file })
}

#[derive(Debug)]
struct FileLockGuard {
    file: File,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        use fs2::FileExt;
        let _ = self.file.file().unlock();
    }
}

impl std::ops::Deref for FileLockGuard {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl std::ops::DerefMut for FileLockGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
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

fn copy_directory(from: impl AsRef<StdPath>, to: impl AsRef<StdPath>, use_move: bool) {
    _copy_directory(from.as_ref(), to.as_ref(), use_move)
}

fn _copy_directory(from: &StdPath, to: &StdPath, use_move: bool) {
    for dir_entry in walkdir::WalkDir::new(from) {
        let dir_entry = dir_entry.unwrap();
        let path = dir_entry.path();
        let subpath = path.strip_prefix(from).unwrap();
        let target_path = to.join(&subpath);
        if dir_entry.file_type().is_dir() {
            fs_err::create_dir(target_path).unwrap();
        } else {
            move_file(path, &target_path, use_move).unwrap();
        }
    }
}

fn is_path_of_executable(path: &Utf8Path) -> bool {
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

    // without shebang
    fn executable_code(&self) -> String {
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
        )
    }

    fn generate_executable(
        &self,
        dest: &Path,
        python_path: &Path,
        site_packages: &Path,
    ) -> std::io::Result<RecordEntry> {
        let dest = match dest.is_dir() {
            true => dest.join(&self.name),
            false => dest.to_owned(),
        };
        let code = self.executable_code();
        generate_executable(&dest, python_path, &code, site_packages)
    }
}

fn generate_executable(
    dest: &Path,
    python_path: &Path,
    code: &str,
    site_packages: &Path,
) -> std::io::Result<RecordEntry> {
    let shebang = format!("#!{}", python_path);
    #[cfg(unix)]
    {
        _generate_executable(
            &dest,
            format!("{}\n{}", shebang, code).as_bytes(),
            site_packages,
        )
    }

    #[cfg(windows)]
    {
        // Generate .exe wrappers for python scripts.
        // This uses the same launcher as the python module "distlib", which is what pip uses
        // to generate exe wrappers.
        // The launcher needs to be concatenated with a shebang and a zip of the code to be executed.
        // The launcher code is at https://bitbucket.org/vinay.sajip/simple_launcher/

        // 32 bit launchers and GUI launchers are not supported (yet)
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
        _generate_executable(&dest.with_extension("exe"), &wrapper, site_packages)
    }
}

fn _generate_executable(
    dest: &Path,
    bytes: &[u8],
    site_packages: &Path,
) -> std::io::Result<RecordEntry> {
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
    f.write_all(bytes)?;
    Ok(RecordEntry {
        path: relative_path(site_packages, dest)
            .try_into()
            .expect(INVALID_UTF8_PATH),
        hash: FileHash::from_reader(bytes),
        filesize: bytes.len() as u64,
    })
}

fn _entrypoints(path: &Path) -> Option<Vec<EntryPoint>> {
    let ini = ini::Ini::load_from_file(path);

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

// fn dist_info_dirname(name: &str, version: &str, hash: &DistributionHash) -> String {
//     format!("{},{},{}", name, version, hash)
// }

fn move_file(
    src: impl AsRef<StdPath>,
    dst: impl AsRef<StdPath>,
    use_move: bool,
) -> std::io::Result<()> {
    _move_file(src.as_ref(), dst.as_ref(), use_move)
}

fn _move_file(src: &StdPath, dst: &StdPath, use_move: bool) -> std::io::Result<()> {
    if use_move {
        fs_err::rename(src, dst)
    } else {
        fs_err::copy(src, dst).map(drop)
    }
}

fn register_distribution_files(
    proj_dirs: &ProjectDirs,
    install_folder: &Path,
    distribution: &Distribution,
    stored_distributions: &mut HashMap<DistributionHash, StoredDistribution>,
    options: crate::Options,
) -> EResult<()> {
    let dist_info_foldername = distribution.dist_info_name();
    let src_dist_info = install_folder.join(&dist_info_foldername);

    let stored_distrib = StoredDistribution {
        distribution: distribution.clone(),
        installed_via: StoredDistributionType::FromPip,
    };
    let dst_dist_info = proj_dirs
        .dist_infos()
        .join(&stored_distrib.distribution.as_csv());

    // let use_move = can_move_files(&proj_dirs.package_files(), install_folder).unwrap_or(false);
    let use_move = true;

    if dst_dist_info.exists() {
        // add it here, because it may have been installed by a different
        // python version. In that case, the current python version's list
        // may be missing this distribution.
        stored_distributions.insert(distribution.sha.clone(), stored_distrib);
        return Ok(());
    }
    if options.verbose >= 1 {
        println!(
            "Adding {} {} to central store.",
            distribution.name, distribution.version
        );
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

        debug_assert_ne!(file.hash, FileHash("".to_owned()));

        let src = install_folder.join(path);
        let dest = proj_dirs.package_files().join(file.hash.0);
        if options.verbose >= 2 {
            println!("    copying {} to {}", src, dest);
        }

        let res = move_file(&src, &dest, use_move);
        match &res {
            Err(err) if is_not_found(err) => {
                print_error_missing_file_in_record(&distribution, file.path.as_ref())
            }
            _ => {
                res.unwrap();
            }
        };
    }

    copy_directory(&src_dist_info, &dst_dist_info, use_move);
    stored_distributions.insert(distribution.sha.clone(), stored_distrib);
    Ok(())
}

fn register_distribution_files_of_wheel(
    proj_dirs: &ProjectDirs,
    install_folder: &Path,
    distribution: &Distribution,
    stored_distributions: &mut HashMap<DistributionHash, StoredDistribution>,
    options: crate::Options,
) -> EResult<()> {
    let dist_info_foldername = format!("{}-{}.dist-info", distribution.name, distribution.version);
    let src_dist_info = install_folder.join(&dist_info_foldername);

    let stored_distrib = StoredDistribution {
        distribution: distribution.clone(),
        installed_via: StoredDistributionType::FromWheel,
    };
    let dst_record_dir = proj_dirs
        .records()
        .join(&stored_distrib.distribution.as_csv());

    // let use_move = can_move_files(&proj_dirs.package_files(), install_folder).unwrap_or(false);
    let use_move = true;

    if dst_record_dir.exists() {
        // add it here, because it may have been installed by a different
        // python version. In that case, the current python version's list
        // may be missing this distribution.
        stored_distributions.insert(distribution.sha.clone(), stored_distrib);
        return Ok(());
    }
    if options.verbose >= 1 {
        println!(
            "Adding {} {} to central store.",
            distribution.name, distribution.version
        );
    }

    let records = python_wheel::WheelRecord::from_file(&src_dist_info.join("RECORD"))
        .wrap_err("couldn't get dist-info/RECORD")?;
    for file in &records.files {
        let src = install_folder.join(&file.path);
        assert!(src.starts_with(&install_folder));
        let dest = proj_dirs.package_files().join(&file.hash.0);
        if options.verbose >= 2 {
            println!("    moving {} to {}", src, dest);
        }

        let res = move_file(&src, &dest, use_move);
        match &res {
            // TODO: Add check of RECORD during wheel installation before registration.
            //       It must be complete and correct so we should never run into this.
            Err(err) if is_not_found(err) => {
                print_error_missing_file_in_record(&distribution, file.path.as_ref())
            }
            _ => {
                res.unwrap();
            }
        };
    }

    let repo_records_dir = proj_dirs.records().join(distribution.as_csv());
    fs_err::create_dir_all(&repo_records_dir)?;
    records
        .save_to_file(repo_records_dir.join("RECORD"))
        .wrap_err("failed to save RECORD")?;

    stored_distributions.insert(distribution.sha.clone(), stored_distrib);
    Ok(())
}

// fn can_move_files(src: &Path, dst: &Path) -> EResult<bool> {
//     let filename = ".deleteme_rename_test";
//     let src = src.join(filename);
//     let dst = dst.join(filename);
//     fs_err::write(&src, "")?;
//     let can_move = fs_err::rename(src, &dst).is_ok();
//     let _ = fs_err::remove_file(dst);
//     Ok(can_move)
// }

// returns all files recorded in RECORDS, except for .dist-info files
fn records(record: &Path) -> csv::Result<impl Iterator<Item = csv::Result<RecordEntry>>> {
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
                    camino::Utf8Component::Normal(path) => Some(path),
                    _ => None,
                })
                .unwrap();
            let is_dist_info = first.ends_with(".dist-info");

            (!is_dist_info).then(|| record.deserialize(None))
        }))
}

fn install_and_register_distribution_from_file(
    proj_dirs: &ProjectDirs,
    distrib_path: &Path,
    requirement: Requirement,
    python_version: PythonVersion,
    options: Options,
) -> EResult<()> {
    let tmp_dir = tempdir::TempDir::new_in(proj_dirs.tmp(), "virtpy_wheel")?;
    let (distrib_path, _wheel_tmp_dir) = match distrib_path.extension().unwrap() {
        "whl" => (distrib_path.to_owned(), None),
        _ => {
            let python = python_detection::detect_from_version(python_version)?;
            let (wheel_path, tmp_dir) = convert_to_wheel(&python, proj_dirs, distrib_path)?;
            (wheel_path, Some(tmp_dir))
        }
    };
    assert!(distrib_path.extension().unwrap() == "whl");
    python_wheel::unpack_wheel(
        &distrib_path,
        tmp_dir.path().try_into().expect(INVALID_UTF8_PATH),
    )?;

    let distrib = Distribution {
        name: requirement.name,
        version: requirement.version,
        sha: requirement.available_hashes.into_iter().next().unwrap(),
    };

    register_new_distribution(options, distrib, proj_dirs, python_version, tmp_dir)?;

    Ok(())
}

// Converts a non-wheel distribution of some type into a wheel.
// This can be a egg, a tarball (typically gzipped, but other compression algorithms are possible as well as uncompressed),
// or a zip file.
//
// Returns the path to the wheel and the TempDir that contains the wheel file.
// The TempDir needs to be preserved until the wheel has been used or copied elsewhere as it'll be
// deleted with the TempDir.
fn convert_to_wheel(
    python: &Path,
    proj_dirs: &ProjectDirs,
    distrib_path: impl AsRef<Path>,
) -> EResult<(PathBuf, tempdir::TempDir)> {
    let path = distrib_path.as_ref();
    _convert_to_wheel(python, proj_dirs, path)
        .wrap_err_with(|| eyre!("failed to convert file to wheel: {}", path))
}

fn _convert_to_wheel(
    python: &Path,
    proj_dirs: &ProjectDirs,
    distrib_path: &Path,
) -> EResult<(PathBuf, tempdir::TempDir)> {
    let output_dir = tempdir::TempDir::new_in(proj_dirs.tmp(), "convert_to_wheel")?;

    check_status(
        std::process::Command::new(python)
            .args(&["-m", "pip", "wheel", "--no-cache-dir", "--wheel-dir"])
            .arg(output_dir.path())
            .arg(distrib_path),
    )?;

    let output_files = output_dir
        .path()
        .read_dir()?
        .collect::<Result<Vec<_>, _>>()?;
    match output_files.len() {
        1 => {
            let wheel_path = output_files
                .into_iter()
                .next()
                .unwrap()
                .path()
                .try_into()
                .expect(INVALID_UTF8_PATH);
            Ok((wheel_path, output_dir))
        }
        _ => Err(eyre!("wheel generation created more than one file")),
    }
}

fn install_and_register_distributions(
    python_path: &Path,
    proj_dirs: &ProjectDirs,
    distribs: &[Requirement],
    python_version: PythonVersion,
    options: Options,
) -> EResult<()> {
    if options.verbose >= 1 {
        println!("Adding {} new distributions", distribs.len());
    }
    if distribs.is_empty() {
        return Ok(());
    }

    let tmp_dir = tempdir::TempDir::new_in(proj_dirs.tmp(), "virtpy")?;
    let tmp_requirements = tmp_dir.as_ref().join("__tmp_requirements.txt");
    let reqs = serialize_requirements_txt(distribs);
    fs_err::write(&tmp_requirements, reqs)?;
    let output = std::process::Command::new(python_path)
        .args(&["-m", "pip", "install", "--no-deps", "--no-compile", "-r"])
        .arg(&tmp_requirements)
        .arg("-t")
        .arg(tmp_dir.as_ref())
        .arg("-v")
        .output()?;
    if !output.status.success() {
        panic!(
            "pip error:\n{}",
            std::str::from_utf8(&output.stderr).unwrap()
        );
    }

    let pip_log = String::from_utf8(output.stdout)?;

    let new_distribs = newly_installed_distributions(&pip_log);
    register_new_distributions(
        options,
        new_distribs,
        distribs.len(),
        proj_dirs,
        pip_log,
        python_version,
        tmp_dir,
    )?;

    Ok(())
}

fn register_new_distributions(
    options: Options,
    new_distribs: Vec<Distribution>,
    n_distribs_requested: usize,
    proj_dirs: &ProjectDirs,
    pip_log: String,
    python_version: PythonVersion,
    tmp_dir: tempdir::TempDir,
) -> EResult<()> {
    if options.verbose >= 1 {
        if new_distribs.len() != n_distribs_requested {
            // either an error or a sign that the filters in new_dependencies()
            // need to be improved
            println!(
                "Only found {} of {} distributions",
                new_distribs.len(),
                n_distribs_requested
            );

            let _ = fs_err::write(proj_dirs.data().join("pip.log"), pip_log);
        }
    }
    if options.verbose >= 2 {
        for distrib in new_distribs.iter() {
            println!(
                "    New distribution: {}=={}, {}",
                distrib.name, distrib.version, distrib.sha.0
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
            tmp_dir.path().try_into().expect(INVALID_UTF8_PATH),
            &distrib,
            stored_distributions,
            options,
        )
        .wrap_err_with(|| {
            eyre!(
                "failed to add distribution files for {} {}",
                distrib.name,
                distrib.version
            )
        })?;
    }
    all_stored_distributions.save()?;
    Ok(())
}

// Usable only for our own installation from wheel files
fn register_new_distribution(
    options: Options,
    distrib: Distribution,
    proj_dirs: &ProjectDirs,
    python_version: PythonVersion,
    tmp_dir: tempdir::TempDir,
) -> EResult<()> {
    if options.verbose >= 2 {
        println!(
            "    New distribution: {}=={}, {}",
            distrib.name, distrib.version, distrib.sha
        );
    }
    let mut all_stored_distributions = StoredDistributions::load(proj_dirs)?;
    let stored_distributions = all_stored_distributions
        .0
        .entry(python_version.as_string_without_patch())
        .or_default();
    register_distribution_files_of_wheel(
        proj_dirs,
        tmp_dir.path().try_into().expect(INVALID_UTF8_PATH),
        &distrib,
        stored_distributions,
        options,
    )
    .wrap_err_with(|| {
        eyre!(
            "failed to add distribution files for {} {}",
            distrib.name,
            distrib.version
        )
    })?;
    all_stored_distributions.save()?;
    Ok(())
}

fn new_dependencies(
    requirements: &[Requirement],
    proj_dirs: &ProjectDirs,
    python_version: PythonVersion,
) -> EResult<Vec<Requirement>> {
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

fn wheel_is_already_registered(
    wheel_hash: DistributionHash,
    proj_dirs: &ProjectDirs,
    python_version: PythonVersion,
) -> EResult<bool> {
    let stored_distributions = StoredDistributions::load(proj_dirs)?;
    Ok(stored_distributions
        .0
        .get(&python_version.as_string_without_patch())
        .map_or(false, |deps| deps.contains_key(&wheel_hash)))
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
            data_dir: proj_dirs
                .data_dir()
                .to_owned()
                .try_into()
                .expect(INVALID_UTF8_PATH),
        })
    }

    fn from_path(data_dir: PathBuf) -> Self {
        Self { data_dir }
    }

    fn from_existing_path(data_dir: PathBuf) -> EResult<Self> {
        let proj_dirs = Self::from_path(data_dir.clone());
        for necessary_subdir in proj_dirs._paths() {
            if !data_dir.join(&necessary_subdir).exists() {
                bail!("missing directory {}", necessary_subdir);
            }
        }
        Ok(proj_dirs)
    }

    fn create_dirs(&self) -> std::io::Result<()> {
        fs_err::create_dir_all(self.data())?;
        for path in self._paths() {
            fs_err::create_dir(path).or_else(ignore_target_exists)?;
        }
        Ok(())
    }

    fn _paths(&self) -> impl IntoIterator<Item = PathBuf> {
        [
            self.installations(),
            self.dist_infos(),
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

    fn dist_infos(&self) -> PathBuf {
        self.data().join("dist-infos")
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

    // TODO: use everywhere possible
    fn package_file(&self, hash: &FileHash) -> PathBuf {
        self.package_files().join(&hash.0)
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

    fn installed_distributions(&self) -> impl Iterator<Item = StoredDistribution> + '_ {
        self.dist_infos()
            .read_dir()
            .unwrap()
            .map(|e| (e.unwrap(), StoredDistributionType::FromPip))
            .chain(
                self.records()
                    .read_dir()
                    .unwrap()
                    .map(|e| (e.unwrap(), StoredDistributionType::FromWheel)),
            )
            .map(|(dist_info_entry, installed_via)| StoredDistribution {
                installed_via,
                distribution: Distribution::from_store_name(
                    dist_info_entry
                        .path()
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap(),
                ),
            })
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
    let (_, distrib_name, version) = lazy_regex::regex_captures!(
        r"([a-zA-Z_][a-zA-Z0-9_-]*)-(\d*!.*|\d*\..*)\.dist-info",
        dirname
    )
    .unwrap();
    (distrib_name, version)
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

    fn metadata_dir(&self) -> PathBuf {
        self.location().join(CENTRAL_METADATA)
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

fn path_to_virtpy(path_override: &Option<PathBuf>) -> &Path {
    path_override
        .as_deref()
        .unwrap_or_else(|| DEFAULT_VIRTPY_PATH.as_ref())
}

fn shim_info(proj_dirs: &ProjectDirs) -> EResult<ShimInfo> {
    Ok(ShimInfo {
        proj_dirs,
        virtpy_exe: PathBuf::try_from(
            std::env::current_exe().wrap_err("failed to find the running executable's path")?,
        )?,
    })
}

fn main() -> EResult<()> {
    color_eyre::install()?;

    let opt = Opt::from_args();
    let options = Options {
        verbose: opt.verbose,
    };

    // There's currently a bug with zip archive extraction on Windows where it will fail if the
    // destination uses extended length syntax. canonicalize() will always return such paths.
    // As a workaround, we use current_dir().join(dir) to get the absolute path.
    let current_dir =
        PathBuf::try_from(std::env::current_dir().wrap_err("can't get current dir")?)?;
    let proj_dirs = match opt.project_dir {
        Some(dir) => ProjectDirs::from_existing_path(current_dir.join(&dir))?,
        None => {
            let proj_dirs = ProjectDirs::new().ok_or_else(|| eyre!("failed to get proj dirs"))?;
            proj_dirs.create_dirs()?;
            proj_dirs
        }
    };

    match opt.cmd {
        Command::Add {
            requirements,
            virtpy_path,
        } => {
            fn add_requirements(
                proj_dirs: &ProjectDirs,
                virtpy_path: Option<PathBuf>,
                options: Options,
                requirements: PathBuf,
            ) -> EResult<()> {
                let virtpy = CheckedVirtpy::new(path_to_virtpy(&virtpy_path))?;
                let requirements = fs_err::read_to_string(requirements)?;
                let requirements = python_requirements::read_requirements_txt(&requirements);

                virtpy_add_dependencies(&proj_dirs, &virtpy, requirements, options)?;
                Ok(())
            }

            add_requirements(&proj_dirs, virtpy_path, options, requirements)
                .wrap_err("failed to add requirements")?;
        }
        Command::Remove {
            distributions,
            virtpy_path,
        } => {
            let virtpy = CheckedVirtpy::new(path_to_virtpy(&virtpy_path))?;
            virtpy_remove_dependencies(&virtpy, distributions.into_iter().collect())?;
        }
        Command::New {
            path,
            python,
            without_pip_shim,
            ..
        } => {
            let path = path.unwrap_or_else(|| PathBuf::from(DEFAULT_VIRTPY_PATH));

            let shim_info = (!without_pip_shim)
                .then(|| shim_info(&proj_dirs))
                .transpose()?;
            python_detection::detect(&python)
                .and_then(|python_path| {
                    create_virtpy(&proj_dirs, &python_path, &path, None, shim_info)
                })
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
                    .wrap_err(eyre!("failed to uninstall {}", package))
                {
                    Ok(()) => println!("uninstalled {}.", package),
                    Err(err) => eprintln!("{:?}", err),
                }
            }
        }
        Command::InternalStore(InternalStoreCmd::Gc { remove }) => {
            internal_store::collect_garbage(&proj_dirs, remove, options)?;
        }
        Command::Path(PathCmd::Bin) | Command::Path(PathCmd::Executables) => {
            println!("{}", proj_dirs.executables());
        }
        Command::InternalStore(InternalStoreCmd::Stats {
            bytes,
            binary_prefix,
        }) => {
            let human_readable = !bytes;
            internal_store::print_stats(&proj_dirs, options, human_readable, binary_prefix)?;
        }
        Command::InternalStore(InternalStoreCmd::Verify) => {
            internal_store::print_verify_store(&proj_dirs);
        }
        Command::InternalUseOnly(InternalUseOnly::AddFromFile { virtpy, file }) => {
            let virtpy = CheckedVirtpy::new(&virtpy)?;
            virtpy_add_dependency_from_file(&proj_dirs, &virtpy, &file, options)?;
        }
    }

    Ok(())
}

// // Related: https://www.python.org/dev/peps/pep-0625/  -- File name of a Source Distribution
// //          Contains a link to a few other PEPs.
// //          PEP 503 defines the concept of a normalized distribution name.
// //          https://www.python.org/dev/peps/pep-0503/#normalized-names
// fn normalized_distribution_name(name: &str) -> String {
//     _escape(name, "-")
// }

// Following https://packaging.python.org/specifications/binary-distribution-format/#escaping-and-unicode
// This is important because the wheel name components may contain "-" characters,
// but those are separators in a wheel name.
// We need this because the dist-info and data directory contain the normalized distrib name.
// We may have to add version normalization, if we ever get unnormalized ones.
fn normalized_distribution_name_for_wheel(distrib_name: &str) -> String {
    _escape(distrib_name, "_")
}

fn _escape(string: &str, replace_with: &str) -> String {
    let pattern = lazy_regex::regex!(r"[-_.]+");
    pattern.replace_all(string, replace_with).to_lowercase()
}

// TODO: refactor
fn virtpy_remove_dependencies(
    virtpy: &CheckedVirtpy,
    dists_to_remove: HashSet<String>,
) -> EResult<()> {
    let dists_to_remove = dists_to_remove
        .into_iter()
        .map(|name| normalized_distribution_name_for_wheel(&name))
        .collect::<HashSet<_>>();

    let site_packages = virtpy.site_packages();

    let mut dist_infos = vec![];

    let site_packages_std: &StdPath = site_packages.as_ref();

    // TODO: detect distributions that aren't installed
    for dir_entry in site_packages_std.fs_err_read_dir()? {
        let dir_entry = dir_entry?;
        // use fs_err::metadata instead of DirEntry::metadata so it traverses symlinks
        // as dist-info dirs are currently symlinked in.
        let filetype = fs_err::metadata(dir_entry.path())?.file_type();
        if !filetype.is_dir() {
            continue;
        }
        let dirname = dir_entry
            .file_name()
            .into_string()
            .expect(INVALID_UTF8_PATH);

        if dirname.ends_with(".dist-info") {
            dist_infos.push(dirname);
        }
    }

    dist_infos.retain(|name| {
        let dist = name.split("-").next().unwrap();
        dists_to_remove.contains(dist)
    });

    let mut files_to_remove = vec![];
    // TODO: remove executables (entrypoints)
    for info in dist_infos {
        let dist_infos = site_packages.join(&info);
        let record_file = dist_infos.join("RECORD");
        for file in records(&record_file)? {
            let file = file?;

            let path = site_packages.join(file.path);
            // NO ESCAPE
            if !path.starts_with(virtpy.location()) {
                continue;
            }

            if path.extension() == Some("py".as_ref()) {
                files_to_remove.push(path.with_extension("pyc"));
            }
            files_to_remove.push(path);
        }

        // NOTE: when dist-infos will not be symlinked in, this will cause an error
        //       when file deletion is attempted.
        files_to_remove.push(dist_infos);
    }

    // Collect the directories so they can be deleted, if empty.
    // Sorted so the contained directories are deleted before the containing directories.
    //
    // NOTE: It seems this doesn't quite catch everything.
    //       When deleting mypy for example, there may be some empty directories left
    //       (output of `tree`):
    //
    //       .venv/lib/python3.8/site-packages/mypy
    //       └── typeshed
    //       ├── stdlib
    //       └── third_party
    //
    //       3 directories, 0 files
    //
    //       maybe we need to take into account *.dist-info/top_level.txt for this.
    let directories = files_to_remove
        .iter()
        // parent() should never return None,
        // but it's gonna return an error anyway when deletion is attempted.
        .filter_map(|path| path.parent())
        .collect::<HashSet<_>>();
    let directories = directories
        .into_iter()
        .sorted_by_key(|path| std::cmp::Reverse(path.iter().count()))
        .collect::<Vec<_>>();

    // TODO: if an error occured, don't delete the dist-info, especially not the RECORD
    //       so deletion can retry.
    for path in &files_to_remove {
        assert!(path.starts_with(&site_packages));

        if false {
            if path.extension() != Some("pyc".as_ref()) {
                println!("deleting {}", path);
            }
        } else {
            // not using fs_err here, because we're not bubbling the error up
            if let Err(e) = std::fs::remove_file(&path).or_else(ignore_target_doesnt_exist) {
                eprintln!("failed to delete {}: {}", path, e);
            }
        }
    }

    for dir in directories {
        assert!(dir.starts_with(&site_packages));
        if dir == site_packages {
            continue;
        }

        // It'd be nice if we could ignore errors for directory not existing and dir not being empty
        // and report all others, but there is no ErrorKind for directory not existing, so it gets
        // lumped in under `Other`.
        // I don't know if the error message is consistent across OS's or is guaranteed not to change,
        // so I can't distinguish between real errors or false positives.
        let _ = fs_err::remove_dir(dir);
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
) -> EResult<InstalledStatus> {
    let package_folder = proj_dirs.package_folder(&package);

    let python_path = python_detection::detect(&python)?;

    if package_folder.exists() {
        if force {
            delete_executable_virtpy(&proj_dirs, &package)?;
        } else {
            return Ok(InstalledStatus::AlreadyInstalled);
        }
    }

    check_poetry_available()?;

    let tmp_dir = tempdir::TempDir::new_in(proj_dirs.tmp(), &format!("install_{}", package))?;
    let tmp_path = PathBuf::try_from(tmp_dir.path().to_owned())
        .expect(INVALID_UTF8_PATH)
        .join(".venv");

    let virtpy = create_virtpy(
        &proj_dirs,
        &python_path,
        &package_folder,
        None,
        Some(shim_info(proj_dirs)?),
    )?;

    // if anything goes wrong, try to delete the incomplete installation
    let virtpy = scopeguard::guard(virtpy, |virtpy| {
        let _ = virtpy.delete();
    });

    symlink_dir(package_folder, tmp_path)?;

    init_temporary_poetry_project(tmp_dir.path())?;

    let mut cmd = std::process::Command::new("poetry");
    cmd.arg("add").arg(package).current_dir(tmp_dir.path());
    if allow_prereleases {
        cmd.arg("--allow-prereleases");
    }
    match options.verbose {
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
    check_status(&mut cmd).wrap_err("failed to install package into virtpy")?;

    let distrib = virtpy
        .dist_info(package)
        .map(internal_store::stored_distribution_of_installed_dist)?;

    let executables = distrib.executable_names(proj_dirs)?;
    let exe_dir = virtpy.executables();
    let target_dir = proj_dirs.executables();
    for mut exe in executables {
        if cfg!(windows) {
            exe.push_str(".exe");
        };
        symlink_file(exe_dir.join(&exe), target_dir.join(&exe))?;
    }

    // if everything succeeds, keep the venv
    std::mem::forget(virtpy);
    Ok(InstalledStatus::NewlyInstalled)
}

fn hash_of_file_sha256_base64(path: &Path) -> String {
    let hash = _hash_of_file_sha256(path);
    base64::encode_config(hash.as_ref(), base64::URL_SAFE_NO_PAD)
}

fn hash_of_file_sha256_base16(path: &Path) -> String {
    let hash = _hash_of_file_sha256(path);
    base16::encode_lower(hash.as_ref())
}

// fn hash_of_reader_sha256_base16(reader: impl std::io::Read) -> String {
//     let hash = _hash_of_reader_sha256(reader);
//     base16::encode_lower(hash.as_ref())
// }

fn hash_of_reader_sha256_base64(reader: impl std::io::Read) -> String {
    let hash = _hash_of_reader_sha256(reader);
    base64::encode_config(hash.as_ref(), base64::URL_SAFE_NO_PAD)
}

fn _hash_of_file_sha256(path: &Path) -> impl AsRef<[u8]> {
    let file = fs_err::File::open(path).unwrap();
    // significant speed improvement, but not huge
    let file = std::io::BufReader::new(file);
    _hash_of_reader_sha256(file)
}

fn _hash_of_reader_sha256(mut reader: impl std::io::Read) -> impl AsRef<[u8]> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher).unwrap();
    hasher.finalize()
}

fn virtpy_add_dependencies(
    proj_dirs: &ProjectDirs,
    virtpy: &CheckedVirtpy,
    requirements: Vec<Requirement>,
    //python_version: PythonVersion,
    options: Options,
) -> EResult<()> {
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

    link_requirements_into_virtpy(proj_dirs, virtpy, requirements, options)
        .wrap_err("failed to add packages to virtpy")
}

fn virtpy_add_dependency_from_file(
    proj_dirs: &ProjectDirs,
    virtpy: &CheckedVirtpy,
    file: &Path,
    options: Options,
) -> EResult<()> {
    let file_hash = DistributionHash::from_file(file);
    let requirement =
        Requirement::from_filename(file.file_name().unwrap(), file_hash.clone()).unwrap();

    if !wheel_is_already_registered(file_hash.clone(), proj_dirs, virtpy.python_version)? {
        install_and_register_distribution_from_file(
            proj_dirs,
            file,
            requirement.clone(),
            virtpy.python_version,
            options,
        )?;
    }

    link_requirements_into_virtpy(proj_dirs, virtpy, vec![requirement], options)
        .wrap_err("failed to add packages to virtpy")
}

fn is_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

fn delete_executable_virtpy(proj_dirs: &ProjectDirs, package: &str) -> EResult<()> {
    let virtpy_path = proj_dirs.package_folder(&package);
    let virtpy = CheckedVirtpy::new(&virtpy_path)?;
    virtpy.delete()?;

    // delete_global_package_executables
    // Executables in the binary directory are just symlinks.
    // The virtpy deletion has broken some of them, just need to find and delete them.
    for entry in proj_dirs.executables().read_dir()? {
        let entry = entry?;
        let target = fs_err::read_link(entry.path())?;
        // TODO: switch to .try_exists() when stable
        if !target.exists() {
            fs_err::remove_file(entry.path())?;
        }
    }
    Ok(())
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
    with_pip_shim: Option<ShimInfo>,
) -> EResult<CheckedVirtpy> {
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
            eyre!(
                "failed to generate an unused virtpy path in {} attempts",
                n_max_attempts
            )
        })?;

    let prompt = prompt
        .as_deref()
        .or(path.file_name())
        .unwrap_or(DEFAULT_VIRTPY_PATH);
    _create_virtpy(central_path, python_path, path, prompt, with_pip_shim)
}

struct ShimInfo<'a> {
    proj_dirs: &'a ProjectDirs,
    // TODO: make this part optional
    //       Having a backreference to the virtpy that created the venv is necessary
    //       for the unit tests to stay isolated, but it also means
    //       that you can't take the virtpy executable in a regular installation
    //       and move it to a different location without all venvs it created breaking.
    //       Regular venvs should try to find virtpy on the PATH.
    virtpy_exe: PathBuf,
}

fn _create_virtpy(
    central_path: PathBuf,
    python_path: &Path,
    path: &Path,
    prompt: &str,
    with_pip_shim: Option<ShimInfo>,
) -> EResult<CheckedVirtpy> {
    _create_bare_venv(python_path, &central_path, prompt)?;

    fs_err::create_dir(path)?;
    let path = canonicalize(path)?;
    ensure_toplevel_symlinks_exist(&central_path, &path)?;

    let path_: &StdPath = path.as_ref();
    let abs_path: PathBuf = path_
        .fs_err_canonicalize()?
        .try_into()
        .expect(INVALID_UTF8_PATH);
    {
        let metadata_dir = central_path.join(CENTRAL_METADATA);
        fs_err::create_dir(&metadata_dir)?;
        fs_err::write(metadata_dir.join("link_location"), abs_path.as_str())?;
    }

    {
        let link_metadata_dir = path.join(LINK_METADATA);
        fs_err::create_dir(&link_metadata_dir)?;
        fs_err::write(link_metadata_dir.join("link_location"), abs_path.as_str())?;

        debug_assert!(central_path.is_absolute());
        fs_err::write(
            link_metadata_dir.join("central_location"),
            central_path.as_str(),
        )?;
    }

    let checked_virtpy = CheckedVirtpy {
        link: path.to_owned(),
        backing: central_path,
        // Not all users of this function may need the python version, but it's
        // cheap to get and simpler to just always query.
        // Could be easily replaced with a token-struct that could be converted
        // to a full CheckedVirtpy on demand.
        python_version: python_version(python_path)?,
    };
    if let Some(shim_info) = with_pip_shim {
        add_pip_shim(&checked_virtpy, shim_info).wrap_err("failed to add pip shim")?;
    }

    Ok(checked_virtpy)
}

fn canonicalize(path: &Path) -> EResult<PathBuf> {
    Ok(PathBuf::try_from(path.canonicalize()?)?)
}

fn ensure_toplevel_symlinks_exist(backing_location: &Path, virtpy_location: &Path) -> EResult<()> {
    for entry in backing_location.read_dir()? {
        let entry = entry?;
        let entry_path: PathBuf = entry.path().try_into().expect(INVALID_UTF8_PATH);
        let entry_name = entry_path.file_name().unwrap(); // guaranteed to exist

        if entry_name == CENTRAL_METADATA {
            continue;
        }

        let target = virtpy_location.join(entry_name);
        // If entry is a symlink, get the filetype for what it's pointed at.
        // I'm assuming that you need to create a directory symlink if you're
        // creating a symlink to a symlink to a dir.
        let filetype = fs_err::metadata(&entry_path)?.file_type();
        let res = if filetype.is_dir() {
            symlink_dir(&entry_path, &target)
        } else if filetype.is_file() {
            symlink_file(&entry_path, &target)
        } else {
            eyre::bail!(
                "virtpy backing contains file that's neither directory nor file: {}",
                entry_path
            )
        };
        res.or_else(ignore_target_exists)?;
    }
    Ok(())
}

fn add_pip_shim(virtpy: &CheckedVirtpy, shim_info: ShimInfo<'_>) -> EResult<()> {
    let target_path = virtpy.site_packages().join("pip");
    let shim_zip = include_bytes!("../pip_shim/pip_shim.zip");
    let mut archive = zip::read::ZipArchive::new(std::io::Cursor::new(shim_zip))
        .expect("internal error: invalid archive for pip shim");
    archive
        .extract(&target_path)
        .wrap_err_with(|| eyre!("failed to extract pip shim archive to {}", target_path))?;

    let entry_point = EntryPoint {
        name: "pip".to_owned(),
        module: "pip".to_owned(),
        qualname: Some("main".to_owned()),
    };
    let _ = entry_point.generate_executable(
        &virtpy.executables(),
        &virtpy.python(),
        &virtpy.site_packages(),
    )?;
    virtpy.set_has_pip_shim();
    virtpy.set_metadata("virtpy_exe", shim_info.virtpy_exe.as_str())?;
    virtpy.set_metadata("proj_dir", shim_info.proj_dirs.data().as_str())?;

    Ok(())
}

#[allow(unused)]
enum VirtpyLinkStatus {
    Ok { matching_virtpy: PathBuf },
    WrongLocation { should: PathBuf, actual: PathBuf },
    Dangling { target: PathBuf },
}

fn virtpy_link_status(virtpy_link_path: &Path) -> EResult<VirtpyLinkStatus> {
    let supposed_location = virtpy_link_supposed_location(virtpy_link_path)
        .wrap_err("failed to read original location of virtpy")?;
    if !paths_match(virtpy_link_path.as_ref(), supposed_location.as_ref()).unwrap() {
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

fn paths_match(virtpy: &StdPath, link_target: &StdPath) -> EResult<bool> {
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

fn virtpy_status(virtpy_path: &Path) -> EResult<VirtpyStatus> {
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

    if !paths_match(virtpy_path.as_ref(), link_target.as_ref()).unwrap() {
        return Ok(VirtpyStatus::Orphaned {
            link: link_location,
        });
    }

    Ok(VirtpyStatus::Ok {
        matching_link: link_location,
    })
}

fn _create_bare_venv(python_path: &Path, path: &Path, prompt: &str) -> EResult<()> {
    check_status(
        std::process::Command::new(python_path)
            .args(&["-m", "venv", "--without-pip", "--prompt", prompt])
            .arg(&path)
            .stdout(std::process::Stdio::null()),
    )
    .map(drop)
    .wrap_err_with(|| eyre!("failed to create virtpy {}", path))
}

fn check_poetry_available() -> EResult<()> {
    pathsearch::find_executable_in_path("poetry")
        .map(drop)
        .ok_or_else(|| eyre!("this command requires poetry to be installed and on the PATH. (https://github.com/python-poetry/poetry)"))
}

fn init_temporary_poetry_project(path: &StdPath) -> EResult<()> {
    check_status(
        std::process::Command::new("poetry")
            .current_dir(&path)
            .args(&["init", "-n"])
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
    let entry_name = dist_info.file_name().unwrap();
    let (distrib_name, _version) = package_info_from_dist_info_dirname(entry_name);
    distrib_name == package
}

trait VirtpyPaths {
    fn location(&self) -> &Path;
    fn python_version(&self) -> PythonVersion;
    fn metadata_dir(&self) -> PathBuf;

    fn executables(&self) -> PathBuf {
        executables_path(self.location())
    }

    fn python(&self) -> PathBuf {
        python_path(self.location())
    }

    fn dist_info(&self, package: &str) -> EResult<PathBuf> {
        let package = &normalized_distribution_name_for_wheel(package);
        self.dist_infos()
            .find(|path| dist_info_matches_package(path, package))
            .ok_or_else(|| eyre!("failed to find dist-info for {}", package))
    }

    fn dist_infos(&self) -> Box<dyn Iterator<Item = PathBuf>> {
        Box::new(
            self.site_packages()
                .read_dir()
                .unwrap()
                .map(Result::unwrap)
                .map(|dir_entry| dir_entry.path())
                .map(|std_path| PathBuf::from_path_buf(std_path).expect(INVALID_UTF8_PATH))
                .filter(|path| {
                    path.file_name()
                        .map_or(false, |fn_| fn_.ends_with(".dist-info"))
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
            self.location().join("Lib").join("site-packages")
        }
    }

    fn install_paths(&self) -> EResult<InstallPaths> {
        InstallPaths::detect(self.python())
    }

    fn set_metadata(&self, name: &str, value: &str) -> EResult<()> {
        fs_err::write(self.metadata_dir().join(name), value)?;
        Ok(())
    }

    fn get_metadata(&self, name: &str) -> EResult<Option<String>> {
        fs_err::read_to_string(self.metadata_dir().join(name))
            .map(Some)
            .or_else(|err| {
                if is_not_found(&err) {
                    Ok(None)
                } else {
                    Err(err.into())
                }
            })
    }
}

// The paths where the contents of subdirs of a wheel's data directory should be placed.
// The documentation does not say what these are or where to get them, but it says that it follows
// distutils.commands.install.install and we can seemingly extract them from there.
// Is this correct? Who knows with "standards" like in the python world.
//
// This is a mapping like `{ "headers": "some/path/to/place/headers", "purelib": "other/path" }`.
struct InstallPaths(HashMap<String, PathBuf>);

impl InstallPaths {
    fn detect(python_path: impl AsRef<Path>) -> EResult<Self> {
        let get_paths = |sys_name| {
            format!(
                r#"import json
from distutils import dist
from distutils.command import install

distrib = dist.Distribution({{"name": "{}"}})
inst = install.install(distrib)
inst.finalize_options()

paths = {{
    k: getattr(inst, f"install_{{k}}") for k in install.SCHEME_KEYS
}}
print(json.dumps(paths))"#,
                sys_name
            )
        };

        let get_paths = if cfg!(unix) {
            get_paths("unix_prefix")
        } else {
            // TODO: check that this is correct
            get_paths("nt")
        };

        let output = check_output(
            std::process::Command::new(python_path.as_ref()).args(&["-c", &get_paths]),
        )?;

        Ok(InstallPaths(serde_json::from_str(&output)?))
    }
}

impl VirtpyPaths for CheckedVirtpy {
    fn location(&self) -> &Path {
        &self.link
    }

    fn python_version(&self) -> PythonVersion {
        self.python_version
    }

    fn metadata_dir(&self) -> PathBuf {
        self.location().join(LINK_METADATA)
    }
}

impl CheckedVirtpy {
    fn new(virtpy_link: &Path) -> EResult<Self> {
        match virtpy_link_status(virtpy_link).wrap_err("failed to verify virtpy")? {
            VirtpyLinkStatus::WrongLocation { should, .. } => {
                Err(eyre!("virtpy copied or moved from {}", should))
            }
            VirtpyLinkStatus::Dangling { target } => {
                Err(eyre!("backing storage for virtpy not found: {}", target))
            }
            VirtpyLinkStatus::Ok { matching_virtpy } => Ok(CheckedVirtpy {
                link: canonicalize(virtpy_link)?,
                backing: matching_virtpy,
                python_version: python_version(&python_path(virtpy_link))?,
            }),
        }
        .wrap_err_with(|| {
            eyre!(
                "the virtpy `{}` is broken, please recreate it.",
                virtpy_link,
            )
        })
    }

    // Returns the path of the python installation on which this
    // this virtpy builds
    fn global_python(&self) -> EResult<PathBuf> {
        #[cfg(unix)]
        {
            let python = self.python();
            let python: &StdPath = python.as_ref();
            let python: PathBuf =
                PathBuf::try_from(python.fs_err_canonicalize().wrap_err_with(|| {
                    eyre!(
                        "failed to find path of the global python used by virtpy at {}",
                        self.link
                    )
                })?)
                .expect(INVALID_UTF8_PATH);
            Ok(python)
        }

        #[cfg(windows)]
        {
            let version = python_version(&self.python())?;
            python_detection::detect(&version.as_string_without_patch())
        }
    }

    fn delete(self) -> EResult<()> {
        fs_err::remove_dir_all(self.location())?;
        delete_virtpy_backing(&self.backing)?;
        Ok(())
    }

    fn virtpy_backing(&self) -> VirtpyBacking {
        VirtpyBacking {
            location: self.backing.clone(),
            python_version: self.python_version,
        }
    }

    fn metadata_dir(&self) -> PathBuf {
        self.location().join(LINK_METADATA)
    }

    fn _pip_shim_flag_file(&self) -> PathBuf {
        self.metadata_dir().join("has_pip_shim")
    }

    #[allow(unused)]
    fn has_pip_shim(&self) -> bool {
        self._pip_shim_flag_file().exists()
    }

    fn set_has_pip_shim(&self) {
        // TODO: bubble error up
        let _ = std::fs::write(self._pip_shim_flag_file(), "");
    }
}

fn link_requirements_into_virtpy(
    proj_dirs: &ProjectDirs,
    virtpy: &CheckedVirtpy,
    mut requirements: Vec<Requirement>,
    options: Options,
) -> EResult<()> {
    // Link files into the backing virtpy so that when new top-level directories are
    // created, they are guaranteed to be on the same harddrive.
    // Symlinks for the new dirs are generated after all the files have been liked in.
    let site_packages = virtpy.virtpy_backing().site_packages();

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
        let stored_distrib = match distribution
            .available_hashes
            .iter()
            .find_map(|hash| existing_deps.get(&hash))
        {
            Some(stored_distrib) => stored_distrib,
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

        link_single_requirement_into_virtpy(
            proj_dirs,
            virtpy,
            options,
            &stored_distrib,
            &site_packages,
        )?;
    }

    ensure_toplevel_symlinks_exist(&virtpy.backing, virtpy.location())?;

    Ok(())
}

fn link_single_requirement_into_virtpy(
    proj_dirs: &ProjectDirs,
    virtpy: &CheckedVirtpy,
    options: Options,
    distrib: &StoredDistribution,
    site_packages: &Path,
) -> EResult<()> {
    match distrib.installed_via {
        StoredDistributionType::FromPip => {
            let dist_info_path = proj_dirs.dist_infos().join(distrib.distribution.as_csv());

            let dist_info_foldername = distrib.distribution.dist_info_name();
            let target = site_packages.join(&dist_info_foldername);
            if options.verbose >= 1 {
                println!("symlinking dist info from {} to {}", dist_info_path, target);
            }

            symlink_dir(&dist_info_path, &target)
                .or_else(ignore_target_exists)
                .unwrap();

            link_files_from_record_into_virtpy(
                &dist_info_path,
                virtpy,
                &site_packages,
                proj_dirs,
                &distrib.distribution,
            );
            install_executables(distrib, virtpy, proj_dirs, None)?;
        }
        StoredDistributionType::FromWheel => {
            let record_dir = proj_dirs.records().join(distrib.distribution.as_csv());
            let record_path = record_dir.join("RECORD");

            let mut record = WheelRecord::from_file(record_path)?;

            link_files_from_record_into_virtpy_new(
                &mut record,
                virtpy,
                &site_packages,
                proj_dirs,
                &distrib.distribution,
            )?;
            install_executables(distrib, virtpy, proj_dirs, Some(&mut record))?;

            // ========== This code can be extracted into a fn for "add file with X content to Y path and record it"
            // Add the hash of the installed wheel to the metadata so we can find out
            // later what was installed.
            let hash_path = site_packages
                .join(distrib.distribution.dist_info_name())
                .join(DIST_HASH_FILE);
            let dist_hash = &distrib.distribution.sha.0;
            fs_err::write(&hash_path, &dist_hash)
                .wrap_err("failed to write distribution hash file")?;
            record.files.push(RecordEntry {
                path: hash_path,
                hash: FileHash::from_reader(dist_hash.as_bytes()), // It's a hash of a hash => can't just copy it
                filesize: dist_hash.len() as u64,
            });
            // ==========

            // The RECORD is not linked in, because it doesn't (can't) contain its own hash.
            // Save the (possibly amended) record into the virtpy
            record.save_to_file(
                &site_packages
                    .join(distrib.distribution.dist_info_name())
                    .join("RECORD"),
            )?;
        }
    }
    Ok(())
}

fn link_files_from_record_into_virtpy(
    dist_info_path: &PathBuf,
    virtpy: &CheckedVirtpy,
    site_packages: &Path,
    proj_dirs: &ProjectDirs,
    distribution: &Distribution,
) {
    for record in records(&dist_info_path.join("RECORD"))
        .unwrap()
        .map(Result::unwrap)
    {
        let dest = match remove_leading_parent_dirs(&record.path) {
            Ok(path) => {
                let toplevel_dirs = ["bin", "Scripts", "include", "lib", "lib64", "share"];
                let starts_with_venv_dir = toplevel_dirs.iter().any(|dir| path.starts_with(dir));
                if !starts_with_venv_dir {
                    println!(
                        "{}: attempted file placement outside virtpy, ignoring: {}",
                        distribution.name, record.path
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
        link_file_into_virtpy(proj_dirs, &record, dest, distribution);
    }
}

fn link_files_from_record_into_virtpy_new(
    record: &mut WheelRecord,
    virtpy: &CheckedVirtpy,
    site_packages: &Path,
    proj_dirs: &ProjectDirs,
    distribution: &Distribution,
) -> EResult<()> {
    let data_dir = distribution.data_dir_name();
    // The install paths are not automatically canonicalized.
    // If they are determined through the python in the virtpy link,
    // they will be rooted in the virtpy link.
    // That may cause a hardlink attempt across harddrives, if the target dir
    // doesn't already exist.
    // => use backing
    let paths = virtpy.virtpy_backing().install_paths()?;

    let ensure_dir_exists = |dest: &Path| {
        let dir = dest.parent().unwrap();
        // TODO: assert we're still in the virtpy
        fs_err::create_dir_all(&dir).unwrap();
    };

    for record in &mut record.files {
        match record.path.strip_prefix(&data_dir) {
            Ok(data_dir_subpath) => {
                let mut iter = data_dir_subpath.iter();
                let subdir = iter.next().unwrap();
                let subpath = iter.as_path();
                let base_path = &paths.0[subdir];

                let dest = base_path.join(subpath);
                ensure_dir_exists(&dest);
                let is_executable = subdir == "scripts";
                record.path = relative_path(site_packages, &dest)
                    .try_into()
                    .expect(INVALID_UTF8_PATH);

                if !is_executable {
                    link_file_into_virtpy(proj_dirs, &record, dest, distribution);
                } else {
                    let src = proj_dirs.package_file(&record.hash);
                    let script = fs_err::read_to_string(src)?;

                    // A bit complicated because I'm trying to replace ONLY the first line,
                    // indepently of \n and \r\n without running more code than necessary.
                    if script.lines().next() == Some("#!python") {
                        // lines() iter doesn't have a method for getting the rest of the string, sadly.
                        let first_linebreak = script.find('\n'); // could actually be None, for an empty script.
                        let code = first_linebreak.map_or("", |linebreak| &script[linebreak..]);
                        // Rewriting the shebang (or adding a wrapper for windows) changed the hash and filesize
                        *record = generate_executable(
                            &dest,
                            &virtpy.python(),
                            &code,
                            &virtpy.site_packages(),
                        )?;
                    } else {
                        link_file_into_virtpy(proj_dirs, &record, dest, distribution);
                    }
                }
            }
            Err(_) => {
                let dest = site_packages.join(&record.path);
                ensure_dir_exists(&dest);
                link_file_into_virtpy(proj_dirs, record, dest, distribution);
            }
        };
    }

    Ok(())
}

// Returns a relative path that can be joined onto `base` to get `path`.
// Both `base` and `path` must be absolute.
fn relative_path(base: impl AsRef<Path>, path: impl AsRef<Path>) -> PathBuf {
    _relative_path(base.as_ref(), path.as_ref())
}

fn _relative_path(base: &Path, path: &Path) -> PathBuf {
    // TODO: convert to error
    assert!(
        base.is_absolute() && path.is_absolute() || base.is_relative() && path.is_relative(),
        "paths need to be both relative or both absolute: {:?}, {:?}",
        base,
        path
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
    rel_path
}

fn link_file_into_virtpy(
    proj_dirs: &ProjectDirs,
    record: &RecordEntry, // TODO: take only hash
    dest: PathBuf,
    distribution: &Distribution,
) {
    let src = proj_dirs.package_file(&record.hash);
    match fs_err::hard_link(&src, &dest) {
        Ok(_) => (),
        // TODO: can this error exist? Docs don't say anything about this being a failure
        //       condition
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(err) if is_not_found(&err) => print_error_missing_file_in_record(&distribution, &src),
        Err(err) => panic!("failed to hardlink file from {} to {}: {}", src, dest, err),
    };
}

fn install_executables(
    stored_distrib: &StoredDistribution,
    virtpy: &CheckedVirtpy,
    proj_dirs: &ProjectDirs,
    mut wheel_record: Option<&mut WheelRecord>, // only record when unpacking wheels ourselves
) -> Result<(), color_eyre::Report> {
    let entrypoints = stored_distrib.entrypoints(proj_dirs).unwrap_or(vec![]);
    for entrypoint in entrypoints {
        let executables_path = virtpy.executables();
        let err = || eyre!("failed to install executable {}", entrypoint.name);
        let python_path = executables_path.join("python");
        let record_entry = entrypoint
            .generate_executable(&executables_path, &python_path, &virtpy.site_packages())
            .wrap_err_with(err)?;
        if let Some(wheel_record) = &mut wheel_record {
            wheel_record.files.push(record_entry);
        }
    }
    Ok(())
}

fn print_error_missing_file_in_record(distribution: &Distribution, missing_file: &Path) {
    println!(
        "couldn't find recorded file from {}: {}",
        distribution.name_and_version(),
        missing_file
    )
}

fn remove_leading_parent_dirs(mut path: &Utf8Path) -> Result<&Utf8Path, &Utf8Path> {
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, serde::Serialize, serde::Deserialize)]
struct Distribution {
    name: String,
    version: String,
    sha: DistributionHash,
}

impl Distribution {
    fn from_store_name(store_name: &str) -> Self {
        let (_, name, version, hash) =
            lazy_regex::regex_captures!(r"([^,]+),([^,]+),([^,]+)", store_name).unwrap();

        Self {
            name: name.to_owned(),
            version: version.to_owned(),
            sha: DistributionHash(hash.to_owned()),
        }
    }

    fn as_csv(&self) -> String {
        format!("{},{},{}", self.name, self.version, self.sha)
    }

    fn name_and_version(&self) -> String {
        // used for the dist-info directory and some error reports
        // TODO: implement Display?
        format!("{}-{}", self.name, self.version)
    }

    fn dist_info_name(&self) -> String {
        format!("{}-{}.dist-info", self.name, self.version)
    }

    fn data_dir_name(&self) -> String {
        format!("{}-{}.data", self.name, self.version)
    }
}

fn newly_installed_distributions(pip_log: &str) -> Vec<Distribution> {
    let mut installed_distribs = Vec::new();

    let install_url_pattern = lazy_regex::regex!(
        r"Added ([\w_-]+)==(.*) from (https://[^\s]+)/([\w_]+)-[\w_\-\.]+#(sha256=[0-9a-fA-F]{64})"
    );

    for line in pip_log.lines() {
        if let Some(install_captures) = install_url_pattern.captures(line) {
            let get = |idx| install_captures.get(idx).unwrap().as_str().to_owned();
            // false name, may not have right case
            //let name = get(1);
            let version = get(2);
            //let url = get(3);
            let name = get(4);
            let sha = DistributionHash(get(5));

            //installed_distribs.push((url, distribution, version));
            installed_distribs.push(Distribution { version, sha, name })
        } else if line.contains("Added ") {
            // The regex should have matched.
            panic!("2: {}", line);
        }
    }

    installed_distribs
}

#[cfg(test)]
mod test {
    use crate::python_detection::detect;

    use super::*;

    fn test_proj_dirs() -> ProjectDirs {
        let target = Path::new(env!("CARGO_MANIFEST_DIR"));
        let test_proj_dir = target.join("test_cache");
        let proj_dirs = ProjectDirs::from_path(test_proj_dir);
        proj_dirs.create_dirs().unwrap();
        proj_dirs
    }

    #[test]
    fn test_check_poetry_available() -> EResult<()> {
        check_poetry_available()
    }

    // TODO: add test on same mount point as tmp dir and on different one.
    #[test]
    fn test_install_uninstall() -> EResult<()> {
        let proj_dirs = test_proj_dirs();

        let packages = [
            ("tuna", false),
            ("black", true),
            ("pylint", false),
            ("mypy", false),
            ("youtube-dl", false),
            ("vulture", false),
        ];

        // The pip shim calls back to virtpy and for that we need a compiled binary.
        // cargo test doesn't automatically build the executable so we use escargot's CargoBuild
        // to do so.
        let cargo_run = escargot::CargoBuild::new().bin("virtpy").run().unwrap();

        for &(package, allow_prereleases) in &packages {
            let base_cmd = || -> EResult<_> {
                let mut cmd = assert_cmd::Command::from_std(cargo_run.command());
                cmd.arg("--project-dir").arg(proj_dirs.data()).arg("-vv");
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
            assert_ne!(proj_dirs.executables().read_dir().unwrap().count(), 0);

            uninstall_cmd.ok()?;
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
                    sha: DistributionHash(
                        "sha256=bc58d83eb610252fd8de6363e39d4f1d0619c894b0ed24603b881c02e64c7386"
                            .into()
                    )
                },
                Distribution {
                    name: "isort".into(),
                    version: "4.3.21".into(),
                    sha: DistributionHash(
                        "sha256=6e811fcb295968434526407adb8796944f1988c5b65e8139058f2014cbe100fd"
                            .into()
                    )
                },
                Distribution {
                    name: "lazy_object_proxy".into(),
                    version: "1.4.3".into(),
                    sha: DistributionHash(
                        "sha256=a6ae12d08c0bf9909ce12385803a543bfe99b95fe01e752536a60af2b7797c62"
                            .into()
                    )
                },
                Distribution {
                    name: "mccabe".into(),
                    version: "0.6.1".into(),
                    sha: DistributionHash(
                        "sha256=ab8a6258860da4b6677da4bd2fe5dc2c659cff31b3ee4f7f5d64e79735b80d42"
                            .into()
                    )
                },
                Distribution {
                    name: "pylint".into(),
                    version: "2.5.3".into(),
                    sha: DistributionHash(
                        "sha256=d0ece7d223fe422088b0e8f13fa0a1e8eb745ebffcb8ed53d3e95394b6101a1c"
                            .into()
                    )
                },
                Distribution {
                    name: "six".into(),
                    version: "1.15.0".into(),
                    sha: DistributionHash(
                        "sha256=8b74bedcbbbaca38ff6d7491d76f2b06b3592611af620f8426e82dddb04a5ced"
                            .into()
                    )
                },
                Distribution {
                    name: "toml".into(),
                    version: "0.10.1".into(),
                    sha: DistributionHash(
                        "sha256=bda89d5935c2eac546d648028b9901107a595863cb36bae0c73ac804a9b4ce88"
                            .into()
                    )
                },
                Distribution {
                    name: "wrapt".into(),
                    version: "1.12.1".into(),
                    sha: DistributionHash(
                        "sha256=b62ffa81fb85f4332a4f609cab4ac40709470da05643a082ec1eb88e6d9b97d7"
                            .into()
                    )
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
        let entrypoints =
            _entrypoints("test_files/entrypoints.dist-info/entry_points.txt".as_ref()).unwrap();
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

    // This test accesses the same file as the test `loading_old_and_new_stored_distribs_identical`
    // and the function StoredDistributions::load_from() will lock that file.
    // That causes a failure if both tests run concurrently.
    // That's why they are forced to run in series.
    #[test]
    #[serial_test::serial(installed_distribs)]
    fn can_load_old_stored_distribs() -> EResult<()> {
        let old_file = fs_err::File::open("test_files/old_installed_distributions.json")?;
        let old_stored_distribs = StoredDistributions::try_load_old(BufReader::new(old_file))
            .ok_or_else(|| eyre!("failed to load old stored dstributions"))?;

        let new_file = fs_err::read_to_string("test_files/new_installed_distributions.json")?;
        let new_stored_distribs: _StoredDistributions =
            serde_json::from_str(&new_file).wrap_err("failed to deserialize new file format")?;
        assert_eq!(old_stored_distribs, new_stored_distribs);
        Ok(())
    }

    #[test]
    #[serial_test::serial(installed_distribs)]
    fn loading_old_and_new_stored_distribs_identical() -> EResult<()> {
        let old = StoredDistributions::load_from("test_files/old_installed_distributions.json")?;
        let new = StoredDistributions::load_from("test_files/new_installed_distributions.json")?;
        assert_eq!(old, new);
        Ok(())
    }

    #[test]
    fn get_install_paths() -> EResult<()> {
        let proj_dirs = test_proj_dirs();
        let tmp_dir = tempdir::TempDir::new("virtpy_test")?;
        let virtpy_path: Utf8PathBuf = tmp_dir.path().join("install_paths_test").try_into()?;
        let virtpy = create_virtpy(&proj_dirs, &detect("3")?, &virtpy_path, None, None)?;
        let install_paths = virtpy.install_paths()?;
        let required_keys = ["purelib", "platlib", "headers", "scripts", "data"]
            .iter()
            .map(<_>::to_string)
            .collect::<HashSet<_>>();
        let existent_keys = install_paths.0.keys().cloned().collect::<HashSet<_>>();

        let missing = required_keys.difference(&existent_keys).collect::<Vec<_>>();
        assert!(missing.is_empty(), "missing keys: {:?}", missing);
        Ok(())
    }

    #[test]
    fn relative_path_is_correct() {
        // I bet there's a library for this
        let case = |base: &str, path: &str, expected: &str| {
            assert_eq!(relative_path(base, path), Path::new(expected))
        };

        case("/c0/c1/a0/a1/", "/c0/c1/b0/b1", "../../b0/b1");
        case("/c0/c1/a0/a1/a2", "/c0/c1/b0/b1", "../../../b0/b1");
        case("/c0/c1/a0/a1/", "/c0/c1/b0/b1/b2", "../../b0/b1/b2");
        case("/c0/c1/a0/a1/a2", "/c0/c1/b0/b1/b2", "../../../b0/b1/b2");
        case("/c0/c1", "/c0/c1", "");
    }
}
