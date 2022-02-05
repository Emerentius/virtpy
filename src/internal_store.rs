use eyre::{ensure, eyre, WrapErr};
use fs_err::File;
use itertools::Itertools;

use crate::python::wheel::{verify_wheel_contents, MaybeRecordEntry};
use crate::python::{records, Distribution, DistributionHash, EntryPoint, FileHash, PythonVersion};
use crate::venv::{
    virtpy_link_location, virtpy_link_target, virtpy_status, VirtpyBacking, VirtpyBackingStatus,
    VirtpyPaths,
};
use crate::{
    delete_virtpy_backing, package_info_from_dist_info_dirname,
    python::wheel::{RecordEntry, WheelRecord},
    EResult, Options, Path, PathBuf, ProjectDirs, INVALID_UTF8_PATH,
};
use std::{
    collections::HashMap,
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
            Ok(VirtpyBackingStatus::Ok { .. }) => (),
            Ok(VirtpyBackingStatus::Orphaned { link }) => danglers.push((path, link)),
            Err(err) => println!("failed to check {path}: {err}"),
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
                println!("{virtpy_gone_awol} => {target}");
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
                    println!("Removing {name} {version} ({sha})");

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
                        println!("Removing {file}");
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
        let base64_hash = FileHash::from_file(&path).unwrap();
        if base64_hash != FileHash::from_filename(&path) {
            println!("doesn't match hash: {path}, hash = {base64_hash}");
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
        readable_size(total_size_with_duplicates.saturating_sub(total_size))
    );

    if options.verbose >= 1 {
        println!();
        for (distr, dependents) in distribution_dependents {
            println!(
                "{:30} {} dependents    ({})",
                format_args!("{} {}", distr.distribution.name, distr.distribution.version,),
                dependents.len(),
                distr.distribution.sha
            );
            if options.verbose >= 2 {
                for dependent in dependents {
                    let link_location = virtpy_link_location(&dependent).unwrap();
                    print!("    {link_location}");
                    if options.verbose >= 3 {
                        print!("  =>  {dependent}");
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
                .flat_map(RecordEntry::try_from)
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

fn register_distribution_files_of_wheel(
    proj_dirs: &ProjectDirs,
    install_folder: &Path,
    wheel_record: WheelRecord,
    distribution: &Distribution,
    stored_distributions: &mut HashMap<DistributionHash, StoredDistribution>,
    options: crate::Options,
) -> EResult<()> {
    let stored_distrib = StoredDistribution {
        distribution: distribution.clone(),
        installed_via: StoredDistributionType::FromWheel,
    };

    if options.verbose >= 1 {
        println!(
            "Adding {} {} to central store.",
            distribution.name, distribution.version
        );
    }

    for file in &wheel_record.files {
        let src = install_folder.join(&file.path);
        assert!(src.starts_with(&install_folder));
        let dest = proj_dirs.package_file(&file.hash);
        if options.verbose >= 2 {
            println!("    moving {src} to {dest}");
        }

        fs_err::rename(&src, &dest).wrap_err("failed to move file into central store")?;
    }
    let repo_records_dir = proj_dirs.records().join(distribution.as_csv());
    fs_err::create_dir_all(&repo_records_dir)?;
    wheel_record
        .save_to_file(repo_records_dir.join("RECORD"))
        .wrap_err("failed to save RECORD")?;

    // Any error happening prior to the distribution being registered in stored_distributions
    // and saved to disk will result in unreferenced files in the central store which can be
    // removed by a garbage collection run.
    stored_distributions.insert(distribution.sha.clone(), stored_distrib);
    Ok(())
}

/// A [`crate::python::Distribution`] that exists in the internal store.
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
// given distribution is compatible with, so we let other tools decide
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
        crate::python::entrypoints(&self.dist_info_file(proj_dirs, "entry_points.txt")?)
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
    ) -> EResult<Box<dyn Iterator<Item = EResult<MaybeRecordEntry>>>> {
        let record = self.dist_info_file(project_dirs, "RECORD").unwrap();
        Ok(match self.installed_via {
            StoredDistributionType::FromPip => {
                Box::new(records(&record, false)?.map(|rec| Ok(rec?)))
            }
            StoredDistributionType::FromWheel => Box::new(
                WheelRecord::from_file(&record)?
                    .files
                    .into_iter()
                    .map(|entry| entry.into())
                    .map(Ok),
            ),
        })
    }

    // The executables of this distribution that can be added to the global install dir.
    // For wheel installs this is both entrypoints and scripts from the data dir, but
    // for the legacy pip installed distributions it is just the entrypoints.
    pub(crate) fn executable_names(&self, proj_dirs: &ProjectDirs) -> eyre::Result<Vec<String>> {
        let entrypoint_exes = self
            .entrypoints(proj_dirs)
            .unwrap_or_default()
            .into_iter()
            .map(|ep| ep.name)
            .collect::<Vec<_>>();
        let mut exes = entrypoint_exes.clone();
        if self.installed_via == StoredDistributionType::FromWheel {
            let record = WheelRecord::from_file(self.dist_info_file(proj_dirs, "RECORD").unwrap())?;
            let mut data_exes = record.files;
            let script_path = PathBuf::from(self.distribution.data_dir_name()).join("scripts");
            data_exes.retain(|entry| entry.path.starts_with(&script_path));

            let data_exes = data_exes
                .into_iter()
                .map(|entry| entry.path.file_name().unwrap().to_owned())
                .collect_vec();
            let all_exes = entrypoint_exes.iter().chain(data_exes.iter());
            let duplicates = all_exes.duplicates().map(String::as_str).collect_vec();

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

    let install_folder = Path::from_path(tmp_dir.path()).expect(INVALID_UTF8_PATH);
    let src_dist_info = install_folder.join(distrib.dist_info_name());
    let wheel_record = crate::python::wheel::WheelRecord::from_file(&src_dist_info.join("RECORD"))
        .wrap_err("couldn't get dist-info/RECORD")?;

    verify_wheel_contents(install_folder, &wheel_record)
        .wrap_err("failed to verify wheel record")?;

    let mut all_stored_distributions = StoredDistributions::load(proj_dirs)?;
    let stored_distributions = all_stored_distributions
        .0
        .entry(python_version.as_string_without_patch())
        .or_default();
    register_distribution_files_of_wheel(
        proj_dirs,
        install_folder,
        wheel_record,
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

pub(crate) fn wheel_is_already_registered(
    distribution: &Distribution,
    proj_dirs: &ProjectDirs,
    python_version: PythonVersion,
) -> EResult<bool> {
    let mut stored_distributions = StoredDistributions::load(proj_dirs)?;

    let stored_distrib = StoredDistribution {
        distribution: distribution.clone(),
        installed_via: StoredDistributionType::FromWheel,
    };

    let stored_distribs = stored_distributions
        .0
        .entry(python_version.as_string_without_patch());

    if let std::collections::hash_map::Entry::Occupied(deps) = &stored_distribs {
        if deps.get().contains_key(&distribution.sha) {
            return Ok(true);
        }
    };
    // Check if the package has already been installed for another python version.
    // If so, just add it for the current python version.
    // NOTE: This is a holdover from the old pip install method where we used
    //       poetry to generate a requirements file. That file contained
    //       a list of hashes for each package and it was up to us to figure out
    //       if a given package was compatible with a python version.
    //       This approach is now deprecated and so `StoredDistributions` should be
    //       changed to no longer keep this distinction as soon as the residual support
    //       for packages installed via the old method are removed.
    if stored_distributions
        .0
        .values()
        .any(|a| a.contains_key(&distribution.sha))
    {
        // add it here, because it may have been installed by a different
        // python version. In that case, the current python version's list
        // may be missing this distribution.
        stored_distributions
            .0
            .entry(python_version.as_string_without_patch())
            .or_default()
            .insert(distribution.sha.clone(), stored_distrib);
        stored_distributions.save()?;
        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_records() {
        records("test_files/RECORD".as_ref(), false)
            .unwrap()
            .map(Result::unwrap)
            .for_each(drop);
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
