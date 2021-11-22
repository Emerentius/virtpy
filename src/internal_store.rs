use eyre::{ensure, eyre, WrapErr};
use fs_err::File;

use crate::{
    copy_directory, delete_virtpy_backing, hash_of_file_sha256_base64, is_not_found,
    is_path_of_executable, move_file, package_info_from_dist_info_dirname,
    print_error_missing_file_in_record,
    python_requirements::Requirement,
    python_wheel::{RecordEntry, WheelRecord},
    records, remove_leading_parent_dirs, virtpy_link_location, virtpy_link_target, virtpy_status,
    Distribution, DistributionHash, EResult, EntryPoint, FileHash, Options, Path, PathBuf,
    ProjectDirs, PythonVersion, VirtpyBacking, VirtpyPaths, VirtpyStatus, INVALID_UTF8_PATH,
};
use std::{
    collections::{HashMap, HashSet},
    io::{BufReader, Seek},
};

pub(crate) fn collect_garbage(
    proj_dirs: &ProjectDirs,
    remove: bool,
    options: Options,
) -> EResult<()> {
    let mut danglers = vec![];
    for virtpy in proj_dirs.virtpys().read_dir().unwrap() {
        let virtpy = virtpy.unwrap();
        assert!(virtpy.file_type().unwrap().is_dir());
        let path: PathBuf = virtpy.path().try_into().expect(INVALID_UTF8_PATH);

        match virtpy_status(&path) {
            Ok(VirtpyStatus::Ok { .. }) => (),
            Ok(VirtpyStatus::Orphaned { link }) => danglers.push((path, link)),
            Err(err) => println!("failed to check {}: {}", path, err),
        };
    }

    if !danglers.is_empty() {
        println!("found {} missing virtpys.", danglers.len());

        if remove {
            for (backing, link) in danglers {
                debug_assert!(
                    virtpy_link_target(&link).map_or(true, |link_target| link_target != backing)
                );
                delete_virtpy_backing(&backing).unwrap();
            }
        } else {
            println!("If you've moved some of these, recreate new ones in their place as they'll break when the orphaned backing stores are deleted.\nRun `virtpy gc --remove` to delete orphans\n");

            for (target, virtpy_gone_awol) in danglers {
                println!("{} => {}", virtpy_gone_awol, target);
            }
        }
    }

    {
        let unused_dists = unused_distributions(proj_dirs).collect::<Vec<_>>();
        if !unused_dists.is_empty() {
            println!("found {} modules without users.", unused_dists.len());

            if remove {
                let mut stored_distribs = StoredDistributions::load(proj_dirs)?;

                for dist in unused_dists {
                    let path = dist.path(proj_dirs);
                    assert!(path.starts_with(&proj_dirs.data()));

                    let Distribution { name, version, sha } = &dist.distribution;
                    println!("Removing {} {} ({})", name, version, sha);

                    let res = fs_err::remove_dir_all(path);

                    // Remove distribution from list of installed distributions, for all
                    // python versions.
                    // Save after each attempted removal in case a bug causes the removal to fail prematurely
                    let hash = dist.distribution.sha;
                    for python_specific_stored_distribs in stored_distribs.0.values_mut() {
                        python_specific_stored_distribs.remove(&hash);
                    }
                    stored_distribs
                        .save()
                        .wrap_err("failed to save stored distributions")?;

                    res.unwrap();
                }
            }
        }
    }

    {
        let unused_package_files = unused_package_files(proj_dirs).collect::<Vec<_>>();
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
                        println!("Removing {}", file);
                    }
                    fs_err::remove_file(file).unwrap();
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn print_verify_store(proj_dirs: &ProjectDirs) {
    // TODO: if there are errors, link them back to their original distribution
    let mut any_error = false;
    for file in proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
    {
        // the path is also the hash
        let path: PathBuf = file.path().try_into().expect(INVALID_UTF8_PATH);
        let base64_hash = hash_of_file_sha256_base64(&path);
        if base64_hash != path.file_name().unwrap().strip_prefix("sha256=").unwrap() {
            println!("doesn't match hash: {}, hash = {}", path, base64_hash);
            any_error = true;
        }
    }
    if !any_error {
        println!("everything valid");
    }
}

pub(crate) fn print_stats(
    proj_dirs: &ProjectDirs,
    options: Options,
    human_readable: bool,
    use_binary_si_prefix: bool,
) -> EResult<()> {
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
        .map(|(distr, dependents)| {
            Ok(distribution_files
                .get(distr)
                .ok_or_else(|| {
                    eyre::eyre!(
                        "no entry for distribution {},{:?}",
                        distr.distribution.as_csv(),
                        distr.installed_via
                    )
                })?
                .1
                * dependents.len() as u64)
        })
        .sum::<EResult<u64>>()?;

    let readable_size = |size| match human_readable {
        true => bytesize::to_string(size, use_binary_si_prefix),
        false => size.to_string(),
    };
    println!("total space used: {}", readable_size(total_size));
    println!(
        "total space used with duplication: {}",
        readable_size(total_size_with_duplicates)
    );

    println!(
        "total space saved: {}",
        readable_size(total_size_with_duplicates - total_size)
    );

    if options.verbose >= 1 {
        println!();
        for (distr, dependents) in distribution_dependents {
            println!(
                "{:30} {} dependents    ({})",
                format!("{} {}", distr.distribution.name, distr.distribution.version,),
                dependents.len(),
                distr.distribution.sha
            );
            if options.verbose >= 2 {
                for dependent in dependents {
                    let link_location = virtpy_link_location(&dependent).unwrap();
                    print!("    {}", link_location);
                    if options.verbose >= 3 {
                        print!("  =>  {}", dependent);
                    }
                    println!();
                }
            }
        }
    }
    Ok(())
}

fn file_dependents(
    proj_dirs: &ProjectDirs,
    distribution_files: &HashMap<StoredDistribution, (Vec<RecordEntry>, u64)>,
) -> HashMap<FileHash, Vec<StoredDistribution>> {
    let mut dependents = HashMap::new();

    for file in proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|dir_entry| PathBuf::try_from(dir_entry.path()).expect(INVALID_UTF8_PATH))
    {
        let hash = FileHash::from_filename(&file);
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
fn distributions_dependents(proj_dirs: &ProjectDirs) -> HashMap<StoredDistribution, Vec<PathBuf>> {
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
        .map(|entry| PathBuf::try_from(entry.path()).expect(INVALID_UTF8_PATH))
    {
        let virtpy_dirs = VirtpyBacking::from_existing(virtpy_path.clone());
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
) -> HashMap<StoredDistribution, (Vec<RecordEntry>, u64)> {
    proj_dirs
        .installed_distributions()
        .map(|distribution| {
            let records = distribution
                .records(proj_dirs)
                .unwrap()
                .map(Result::unwrap)
                .filter(|record| {
                    // FIXME: files with ../../
                    proj_dirs.package_file(&record.hash).exists()
                })
                .collect::<Vec<_>>();

            let total_size = records.iter().map(|record| record.filesize).sum::<u64>();
            assert_ne!(total_size, 0);
            (distribution, (records, total_size))
        })
        .collect()
}

fn distributions_used(virtpy_dirs: VirtpyBacking) -> impl Iterator<Item = StoredDistribution> {
    virtpy_dirs
        .dist_infos()
        .filter(|dist_info_path| {
            // poetry places a dist-info into the venv for the package
            // whose dependencies are managed by poetry
            fs_err::read_to_string(dist_info_path.join("INSTALLER"))
                .map_or(true, |installer| installer.trim() != "poetry")
        })
        .map(stored_distribution_of_installed_dist)
}

pub(crate) fn stored_distribution_of_installed_dist(
    dist_info_path: impl AsRef<Path>,
) -> StoredDistribution {
    _stored_distribution_of_installed_dist(dist_info_path.as_ref())
}

fn _stored_distribution_of_installed_dist(dist_info_path: &Path) -> StoredDistribution {
    match dist_info_path
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink()
    {
        true => {
            let dir_in_repo = dist_info_path.read_link().unwrap();
            let dirname = dir_in_repo.file_name().unwrap().to_str().unwrap();
            StoredDistribution {
                distribution: Distribution::from_store_name(dirname),
                installed_via: StoredDistributionType::FromPip,
            }
        }
        false => {
            let hash_path = dist_info_path.join(crate::DIST_HASH_FILE);
            let hash = fs_err::read_to_string(hash_path).unwrap();
            let (name, version) =
                package_info_from_dist_info_dirname(dist_info_path.file_name().unwrap());

            StoredDistribution {
                distribution: Distribution {
                    name: name.into(),
                    version: version.into(),
                    sha: DistributionHash(hash),
                },
                installed_via: StoredDistributionType::FromWheel,
            }
        }
    }
}

fn unused_distributions(proj_dirs: &ProjectDirs) -> impl Iterator<Item = StoredDistribution> + '_ {
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
        let dest = proj_dirs.package_file(&file.hash);
        if options.verbose >= 2 {
            println!("    copying {} to {}", src, dest);
        }

        let res = move_file(&src, &dest, use_move);
        match &res {
            Err(err) if is_not_found(err) => {
                print_error_missing_file_in_record(distribution, file.path.as_ref())
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

    let records = crate::python_wheel::WheelRecord::from_file(&src_dist_info.join("RECORD"))
        .wrap_err("couldn't get dist-info/RECORD")?;
    for file in &records.files {
        let src = install_folder.join(&file.path);
        assert!(src.starts_with(&install_folder));
        let dest = proj_dirs.package_file(&file.hash);
        if options.verbose >= 2 {
            println!("    moving {} to {}", src, dest);
        }

        let res = move_file(&src, &dest, use_move);
        match &res {
            // TODO: Add check of RECORD during wheel installation before registration.
            //       It must be complete and correct so we should never run into this.
            Err(err) if is_not_found(err) => {
                print_error_missing_file_in_record(distribution, file.path.as_ref())
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

#[derive(Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize, Clone)]
pub(crate) struct StoredDistribution {
    pub(crate) distribution: Distribution,
    pub(crate) installed_via: StoredDistributionType,
}

#[derive(Debug, Eq, PartialEq, Hash, serde::Serialize, serde::Deserialize, Clone)]
pub(crate) enum StoredDistributionType {
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
pub(crate) struct StoredDistributions(pub(crate) _StoredDistributions, FileLockGuard);

pub(crate) type _StoredDistributions =
    HashMap<String, HashMap<DistributionHash, StoredDistribution>>;

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

    pub(crate) fn entrypoints(&self, proj_dirs: &ProjectDirs) -> Option<Vec<EntryPoint>> {
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
    pub(crate) fn executable_names(
        &self,
        proj_dirs: &ProjectDirs,
    ) -> eyre::Result<HashSet<String>> {
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

    pub(crate) fn load(proj_dirs: &ProjectDirs) -> EResult<Self> {
        Self::load_from(proj_dirs.installed_distributions_log())
    }

    pub(crate) fn load_from(path: impl AsRef<Path>) -> EResult<Self> {
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

pub(crate) fn register_new_distributions(
    options: Options,
    new_distribs: Vec<Distribution>,
    n_distribs_requested: usize,
    proj_dirs: &ProjectDirs,
    pip_log: String,
    python_version: PythonVersion,
    tmp_dir: tempdir::TempDir,
) -> EResult<()> {
    if options.verbose >= 1 && new_distribs.len() != n_distribs_requested {
        // either an error or a sign that the filters in new_dependencies()
        // need to be improved
        println!(
            "Only found {} of {} distributions",
            new_distribs.len(),
            n_distribs_requested
        );

        let _ = fs_err::write(proj_dirs.data().join("pip.log"), pip_log);
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
pub(crate) fn register_new_distribution(
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

pub(crate) fn new_dependencies(
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

pub(crate) fn wheel_is_already_registered(
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
}
