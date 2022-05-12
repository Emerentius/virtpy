use crate::prelude::*;
use eyre::{ensure, eyre, WrapErr};
use fs_err::File;
use itertools::Itertools;

use crate::python::wheel::MaybeRecordEntry;
use crate::python::{records, Distribution, DistributionHash, EntryPoint, FileHash, PythonVersion};
use crate::venv::{
    virtpy_link_location, virtpy_link_target, virtpy_status, VirtpyBacking, VirtpyBackingStatus,
    VirtpyPaths,
};
use crate::Ctx;
use crate::{
    delete_virtpy_backing, package_info_from_dist_info_dirname,
    python::wheel::{RecordEntry, WheelRecord},
    EResult, Path, PathBuf,
};
use std::collections::HashSet;
use std::{
    collections::HashMap,
    io::{BufReader, Seek},
};

pub(crate) fn collect_garbage(ctx: &Ctx, remove: bool) -> EResult<()> {
    let (danglers, errors): (Vec<_>, Vec<_>) = dangling_virtpys(ctx).partition_result();
    for (virtpy, err) in errors {
        let path = virtpy.location();
        println!("failed to check {path}: {err}");
    }

    let mut store_dependencies = StoreDependencies::current(ctx);
    store_dependencies
        .remove_virtpy_dependencies(danglers.iter().map(|(virtpy, _)| virtpy.clone()));

    if !danglers.is_empty() {
        println!("found {} missing virtpys.", danglers.len());

        if remove {
            for (backing, link) in danglers {
                debug_assert!(virtpy_link_target(&link)
                    .map_or(true, |link_target| link_target != backing.location()));
                delete_virtpy_backing(backing.location()).unwrap();
            }
        } else {
            println!("If you've moved some of these, recreate new ones in their place as they'll break when the orphaned backing stores are deleted.\nRun `virtpy gc --remove` to delete orphans\n");

            for (target, virtpy_gone_awol) in danglers {
                let target = target.location();
                println!("{virtpy_gone_awol} => {target}");
            }
        }
    }

    {
        let unused_dists = store_dependencies
            .dist_virtpys
            .iter()
            .filter(|(_, dependents)| dependents.is_empty())
            .map(|(dist, _)| dist)
            .collect_vec();
        if !unused_dists.is_empty() {
            println!("found {} modules without users.", unused_dists.len());

            if remove {
                let mut stored_distribs = StoredDistributions::load(ctx)?;

                for dist in unused_dists {
                    let path = dist.path(ctx);
                    assert!(path.starts_with(&ctx.proj_dirs.data()));

                    let Distribution { name, version, sha } = &dist.distribution;
                    println!("Removing {name} {version} ({sha})");

                    let res = fs_err::remove_dir_all(path);

                    // Remove distribution from list of installed distributions, for all
                    // python versions.
                    // Save after each attempted removal in case a bug causes the removal to fail prematurely
                    let hash = &dist.distribution.sha;
                    for python_specific_stored_distribs in stored_distribs.0.values_mut() {
                        python_specific_stored_distribs.remove(hash);
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
        let unused_package_files = store_dependencies
            .file_dists
            .iter()
            .filter(|(_, dependents)| dependents.is_empty())
            .map(|(file, _)| ctx.proj_dirs.package_file(&file))
            .collect_vec();
        if !unused_package_files.is_empty() {
            println!(
                "found {} package files without distribution dependents.",
                unused_package_files.len()
            );

            if remove {
                let package_files_dir = ctx.proj_dirs.package_files();
                for file in unused_package_files {
                    assert!(file.starts_with(&package_files_dir));
                    if ctx.options.verbose >= 1 {
                        println!("Removing {file}");
                    }
                    fs_err::remove_file(file).unwrap();
                }
            }
        }
    }
    Ok(())
}

fn dangling_virtpys(
    ctx: &Ctx,
) -> impl Iterator<Item = Result<(VirtpyBacking, PathBuf), (VirtpyBacking, eyre::Report)>> {
    ctx.proj_dirs
        .virtpys()
        .read_dir()
        .unwrap()
        .filter_map(|virtpy| {
            let virtpy = virtpy.unwrap();
            assert!(virtpy.file_type().unwrap().is_dir());
            let path = virtpy.utf8_path();
            let status = virtpy_status(&path);
            let virtpy = VirtpyBacking::from_existing(path);

            match status {
                Ok(VirtpyBackingStatus::Ok { .. }) => None,
                Ok(VirtpyBackingStatus::Orphaned { link }) => Some(Ok((virtpy, link))),
                Err(err) => Some(Err((virtpy, err))),
            }
        })
}

type VirtpyDists = HashMap<VirtpyBacking, HashSet<StoredDistribution>>;
type DistVirtpys = HashMap<StoredDistribution, HashSet<VirtpyBacking>>;

type DistFiles = HashMap<StoredDistribution, HashSet<RecordEntry>>;
type FileDists = HashMap<FileHash, HashSet<StoredDistribution>>;

/// Graph of all dependencies and reverse dependencies.
/// Modifying this has NO effect on the actual store.
#[derive(Clone)]
struct StoreDependencies {
    /// Virtpy to Distributions used
    virtpy_dists: VirtpyDists,
    // Distribution -> Virtpys using it
    dist_virtpys: DistVirtpys,
    // Distribution -> Files part of it
    dist_files: DistFiles,
    // Files -> Distributions containing it
    file_dists: FileDists,
}

impl StoreDependencies {
    // Remove all dependencies from graph, recursively.
    // That means, if none of the still existing virtpys depends on a distribution,
    // its files are also removed from the dependency tree.
    fn remove_virtpy_dependencies(&mut self, virtpys: impl IntoIterator<Item = VirtpyBacking>) {
        for virtpy in virtpys {
            if let Some(virtpy_dists) = self.virtpy_dists.remove(&virtpy) {
                for dist_used in virtpy_dists {
                    self.dist_virtpys
                        .get_mut(&dist_used)
                        .unwrap()
                        .remove(&virtpy);
                }
            }
        }

        for (dist, virtpy_deps) in &self.dist_virtpys {
            if virtpy_deps.is_empty() {
                let dist_files = self.dist_files.remove(dist).unwrap();
                for file in dist_files {
                    self.file_dists.get_mut(&file.hash).unwrap().remove(dist);
                }
            }
        }
    }

    fn current(ctx: &Ctx) -> StoreDependencies {
        // For the cases of dependent mappings (distribution -> virtpy using it, dist file -> distribution containing it)
        // we add all cases without dependencies first.
        // We would otherwise miss orphaned entities.
        let mut virtpy_dists = VirtpyDists::new();
        let mut dist_virtpys: DistVirtpys = ctx
            .proj_dirs
            .installed_distributions()
            .map(|dist| (dist, <_>::default()))
            .collect();
        let mut dist_files = DistFiles::new();
        let mut file_dists: FileDists = package_files(ctx)
            .map(|filehash| (filehash, <_>::default()))
            .collect();

        for virtpy_path in ctx
            .proj_dirs
            .virtpys()
            .read_dir()
            .unwrap()
            .map(Result::unwrap)
        {
            let backing = VirtpyBacking::from_existing(virtpy_path.utf8_path());
            let distributions: HashSet<_> = distributions_used(&backing).collect();
            for dist in &distributions {
                dist_virtpys
                    .entry(dist.clone())
                    .or_default()
                    .insert(backing.clone());
            }
            virtpy_dists.insert(backing, distributions);
        }

        for dist in dist_virtpys.keys() {
            let records: HashSet<_> = dist
                .records(ctx)
                .unwrap()
                .map(Result::unwrap)
                .flat_map(RecordEntry::try_from)
                // .filter(|record| {
                //     // FIXME: files with ../../
                //     ctx.proj_dirs.package_file(&record.hash).exists()
                // })
                .collect();

            for record in &records {
                file_dists
                    .entry(record.hash.clone())
                    .or_default()
                    .insert(dist.clone());
            }

            dist_files.insert(dist.clone(), records);
        }

        StoreDependencies {
            virtpy_dists,
            dist_virtpys,
            dist_files,
            file_dists,
        }
    }
}

fn package_files(ctx: &Ctx) -> impl Iterator<Item = FileHash> {
    ctx.proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| FileHash::from_filename(&entry.utf8_path()))
}

pub(crate) fn print_verify_store(ctx: &Ctx) {
    // TODO: if there are errors, link them back to their original distribution
    let mut any_error = false;
    for file in ctx
        .proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
    {
        // the path is also the hash
        let path = file.utf8_path();
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
    ctx: &Ctx,
    human_readable: bool,
    use_binary_si_prefix: bool,
) -> EResult<()> {
    let total_size: u64 = ctx
        .proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|entry| entry.metadata().unwrap().len())
        .sum();

    let deps = StoreDependencies::current(ctx);
    //let (danglers, errors) = dangling_virtpys(ctx);
    // let non_dangling_deps = {
    //     let mut non_dangling = deps.clone();
    //     non_dangling.remove_virtpy_dependencies(danglers.iter().map(|(virtpy, _)| virtpy.clone()));
    // };

    let mut distribution_sizes = HashMap::<_, u64>::new();
    for (dist, files) in &deps.dist_files {
        distribution_sizes.insert(dist.clone(), files.iter().map(|file| file.filesize).sum());
    }

    let total_size_with_duplicates = deps
        .virtpy_dists
        .values()
        .flatten()
        .map(|dists| distribution_sizes[dists])
        .sum();

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

    if ctx.options.verbose >= 1 {
        println!();
        for (distr, dependents) in deps.dist_virtpys {
            println!(
                "{:30} {} dependents    ({})",
                format!("{} {}", distr.distribution.name, distr.distribution.version,),
                dependents.len(),
                distr.distribution.sha
            );
            if ctx.options.verbose >= 2 {
                for dependent in dependents {
                    let dependent = dependent.location();
                    let link_location = virtpy_link_location(dependent).unwrap();
                    print!("    {link_location}");
                    if ctx.options.verbose >= 3 {
                        print!("  =>  {dependent}");
                    }
                    println!();
                }
            }
        }
    }
    Ok(())
}

fn distributions_used(virtpy_dirs: &VirtpyBacking) -> impl Iterator<Item = StoredDistribution> {
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

fn register_distribution_files_of_wheel(
    ctx: &Ctx,
    install_folder: &Path,
    wheel_record: WheelRecord,
    distribution: &Distribution,
    stored_distributions: &mut HashMap<DistributionHash, StoredDistribution>,
) -> EResult<()> {
    let stored_distrib = StoredDistribution {
        distribution: distribution.clone(),
        installed_via: StoredDistributionType::FromWheel,
    };

    if ctx.options.verbose >= 1 {
        println!(
            "Adding {} {} to central store.",
            distribution.name, distribution.version
        );
    }

    for file in &wheel_record.files {
        let src = install_folder.join(&file.path);
        assert!(src.starts_with(&install_folder));
        let dest = ctx.proj_dirs.package_file(&file.hash);
        if ctx.options.verbose >= 2 {
            println!("    moving {src} to {dest}");
        }

        fs_err::rename(&src, &dest).wrap_err("failed to move file into central store")?;
    }
    let repo_records_dir = ctx.proj_dirs.records().join(distribution.as_csv());
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
    fn dist_info_file(&self, ctx: &Ctx, file: &str) -> Option<PathBuf> {
        match self.installed_via {
            StoredDistributionType::FromPip => {
                let file = ctx
                    .proj_dirs
                    .dist_infos()
                    .join(self.distribution.as_csv())
                    .join(file);
                file.exists().then(|| file)
            }
            StoredDistributionType::FromWheel => {
                let record_path = ctx
                    .proj_dirs
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
                    .map(|entry| ctx.proj_dirs.package_file(&entry.hash))
            }
        }
    }

    pub(crate) fn entrypoints(&self, ctx: &Ctx) -> Option<Vec<EntryPoint>> {
        crate::python::entrypoints(&self.dist_info_file(ctx, "entry_points.txt")?)
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
    fn path(&self, ctx: &Ctx) -> PathBuf {
        let base = match self.installed_via {
            StoredDistributionType::FromPip => ctx.proj_dirs.dist_infos(),
            StoredDistributionType::FromWheel => ctx.proj_dirs.records(),
        };
        base.join(self.distribution.as_csv())
    }

    fn records(&self, ctx: &Ctx) -> EResult<Box<dyn Iterator<Item = EResult<MaybeRecordEntry>>>> {
        let record = self.dist_info_file(ctx, "RECORD").unwrap();
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
    pub(crate) fn executable_names(&self, ctx: &Ctx) -> eyre::Result<Vec<String>> {
        let entrypoint_exes = self
            .entrypoints(ctx)
            .unwrap_or_default()
            .into_iter()
            .map(|ep| ep.name)
            .collect::<Vec<_>>();
        let mut exes = entrypoint_exes.clone();
        if self.installed_via == StoredDistributionType::FromWheel {
            let record = WheelRecord::from_file(self.dist_info_file(ctx, "RECORD").unwrap())?;
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

    pub(crate) fn load(ctx: &Ctx) -> EResult<Self> {
        Self::load_from(ctx.proj_dirs.installed_distributions_log())
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
    ctx: &Ctx,
    distrib: Distribution,
    python_version: PythonVersion,
    tmp_dir: tempdir::TempDir,
) -> EResult<()> {
    if ctx.options.verbose >= 2 {
        println!(
            "    New distribution: {}=={}, {}",
            distrib.name, distrib.version, distrib.sha
        );
    }

    let install_folder = tmp_dir.utf8_path();
    let src_dist_info = install_folder.join(distrib.dist_info_name());
    let wheel_record = crate::python::wheel::WheelRecord::from_file(&src_dist_info.join("RECORD"))
        .wrap_err("couldn't get dist-info/RECORD")?;

    // As stated in the wheel format specification
    // https://packaging.python.org/en/latest/specifications/binary-distribution-format/#the-dist-info-directory
    //
    // >During extraction, wheel installers verify all the hashes in RECORD against the file contents.
    // Apart from RECORD and its signatures, installation will fail if any file in the archive is not both
    // mentioned and correctly hashed in RECORD.
    //
    // Pip, THE python package manager, neglected to implement this so now there are lots of invalid wheels
    // in the wild and we have to deal with them. Why am I not surprised?
    //
    // Given that our pip shim calls virtpy non-interactively, we can't inform the user and prompt
    // whether they want to accept corrupted wheels.
    // We could automatically fix the wheels by computing the correct hash. If we simply accepted
    // files into the central store under whatever hash is in the RECORD, it would be trivial to maliciously
    // create collisions and overwrite another distribution's files.
    //
    // TODO: implement auto-fixing of corrupted wheels.
    // verify_wheel_contents(install_folder, &wheel_record)
    //     .wrap_err("failed to verify wheel record")?;

    let mut all_stored_distributions = StoredDistributions::load(ctx)?;
    let stored_distributions = all_stored_distributions
        .0
        .entry(python_version.as_string_without_patch())
        .or_default();
    register_distribution_files_of_wheel(
        ctx,
        install_folder,
        wheel_record,
        &distrib,
        stored_distributions,
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
    ctx: &Ctx,
    distribution: &Distribution,
    python_version: PythonVersion,
) -> EResult<bool> {
    let mut stored_distributions = StoredDistributions::load(ctx)?;

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
