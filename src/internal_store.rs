use crate::prelude::*;
use eyre::{bail, ensure, eyre, WrapErr};
use fs_err::{File, PathExt};
use itertools::Itertools;

use crate::python::wheel::WheelChecked;
use crate::python::{Distribution, DistributionHash, EntryPoint, FileHash};
use crate::venv::{
    virtpy_link_location, virtpy_status, VirtpyBacking, VirtpyBackingStatus, VirtpyPaths,
};
use crate::Ctx;
use crate::{
    delete_virtpy_backing, package_info_from_dist_info_dirname,
    python::wheel::{RecordEntry, WheelRecord},
    Path, PathBuf,
};
use std::collections::HashSet;
use std::marker::PhantomData;
use std::{
    collections::HashMap,
    io::{BufReader, Seek},
};

pub(crate) fn collect_garbage(ctx: &Ctx, remove: bool) -> Result<()> {
    let (_virtpys, problematic_virtpys): (Vec<_>, Vec<_>) =
        all_virtpy_backings(ctx)?.partition_result();

    let mut to_delete = vec![];
    let mut orphaned = vec![];
    let mut any_critical_errors = false;
    for (path, status) in problematic_virtpys {
        match status {
            VirtpyBackingStatus::Orphaned { virtpy } => orphaned.push(virtpy),
            VirtpyBackingStatus::Unlinked => {
                eprintln!("virtpy is not linked: {path}");
                to_delete.push(path)
            }
            VirtpyBackingStatus::Broken { reason, .. } => {
                eprintln!("virtpy is broken: {reason}: {path}");
                to_delete.push(path);
            }
            VirtpyBackingStatus::Unknown(report) => {
                eprintln!("failed to check status of virtpy: {path}");
                eprintln!("{report}");
                any_critical_errors = true;
            }
        }
    }

    if any_critical_errors {
        bail!("aborting due to inability to check some virtpys");
    }

    if !to_delete.is_empty() && remove {
        for virtpy in to_delete {
            if let Err(err) = delete_virtpy_backing(&virtpy) {
                eprintln!("failed to delete virtpy at {virtpy}: {err}")
            }
        }
    }

    if !orphaned.is_empty() {
        println!("found {} missing virtpys.", orphaned.len());

        if remove {
            for backing in &orphaned {
                let backing_path = backing.location();
                // debug_assert!(virtpy_link_target(link)
                //     .map_or(true, |link_target| link_target != backing_path));
                if let Err(err) = delete_virtpy_backing(backing_path) {
                    eprintln!("failed to delete virtpy at {backing_path}: {err}")
                }
            }
        } else {
            println!("If you've moved some of these, recreate new ones in their place as they'll break when the orphaned backing stores are deleted.\nRun `virtpy gc --remove` to delete orphans\n");

            for backing in &orphaned {
                let target = backing.location();
                match backing.get_metadata("link_location") {
                    Ok(Some(link)) => println!("{link} => {target}"),
                    Ok(None) => println!("link missing for {target}"),
                    Err(err) => eprintln!("failed to read link for {target}: {err}"),
                };
                //println!("{virtpy_gone_awol} => {target}");
            }
        }
    }

    let mut store_dependencies = StoreDependencies::current(ctx)?;
    // TODO: add separate flag for removing orphans
    // TODO: make it possible to remove broken virtpys from dependency graph
    //       (if they are even a part of it)
    store_dependencies.remove_virtpy_dependencies(orphaned.iter().cloned());
    // store_dependencies.remove_virtpy_dependencies(to_delete.iter().cloned());

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
                let mut stored_distribs = StoredDistributions::<Exclusive>::load(ctx)?;

                for dist in unused_dists {
                    let path = dist.path(ctx);
                    assert!(path.starts_with(ctx.proj_dirs.data()));

                    let Distribution { name, version, sha } = &dist.distribution;
                    println!("Removing {name} {version} ({sha})");

                    // Remove distribution from list of installed distributions, for all
                    // python versions.
                    // Save after each attempted removal in case a bug causes the removal to fail prematurely
                    let hash = &dist.distribution.sha;
                    stored_distribs.0.remove(hash);
                    stored_distribs
                        .save()
                        .wrap_err("failed to save stored distributions")?;

                    if let Err(err) = fs_err::remove_dir_all(path) {
                        eprintln!(
                            "failed to delete all files of {}: {err}",
                            dist.distribution.name_and_version()
                        );
                    }
                }
            }
        }
    }

    {
        let unused_package_files = store_dependencies
            .file_dists
            .iter()
            .filter(|(_, dependents)| dependents.is_empty())
            .map(|(file, _)| ctx.proj_dirs.package_file(file))
            .collect_vec();
        if !unused_package_files.is_empty() {
            let mut n_unreadable = 0;
            let total_size: u64 = unused_package_files
                .iter()
                .flat_map(|p| match fs_err::metadata(p) {
                    Ok(md) => Ok(md.len()),
                    Err(_) => {
                        n_unreadable += 1;
                        Err(())
                    }
                })
                .sum();
            println!(
                "found {} unused package files. total size: {}{}",
                unused_package_files.len(),
                bytesize::to_string(total_size, false),
                if n_unreadable > 0 {
                    format!(" ({n_unreadable} file sizes not readable)")
                } else {
                    String::new()
                }
            );

            if remove {
                let package_files_dir = ctx.proj_dirs.package_files();
                for file in unused_package_files {
                    assert!(file.starts_with(&package_files_dir));
                    if ctx.options.verbose >= 1 {
                        println!("Removing {file}");
                    }
                    if let Err(err) = fs_err::remove_file(&file) {
                        eprintln!("failed to delete file {file}: {err}");
                    }
                }
            }
        }
    }
    Ok(())
}

fn all_virtpy_backings(
    ctx: &Ctx,
) -> Result<impl Iterator<Item = Result<VirtpyBacking, (PathBuf, VirtpyBackingStatus)>>> {
    Ok(ctx
        .proj_dirs
        .virtpys()
        .read_dir()
        .wrap_err("failed to read virtpy dir")?
        .filter_map(|virtpy| {
            let virtpy = virtpy.unwrap();
            if !(virtpy.file_type().unwrap().is_dir()) {
                return None;
            }
            let path = virtpy.utf8_path();
            Some(virtpy_status(&path).map_err(|e| (path, e)))
        }))
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
    // TODO: exclude these from stats
    #[allow(unused)]
    broken_backing_virtpys: Vec<PathBuf>,
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
                        .expect("internal error: dist's dependents not in StoreDependencies")
                        .remove(&virtpy);
                }
            }
        }

        for (dist, virtpy_deps) in &self.dist_virtpys {
            if virtpy_deps.is_empty() {
                let dist_files = self
                    .dist_files
                    .remove(dist)
                    .expect("internal error: dist's files not in StoreDependencies");
                for file in dist_files {
                    self.file_dists
                        .get_mut(&file.hash)
                        .expect("internal error: file's dependents not in StoreDependencies")
                        .remove(dist);
                }
            }
        }
    }

    fn current(ctx: &Ctx) -> Result<StoreDependencies> {
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
        let mut file_dists = package_files(ctx)?
            .map_ok(|filehash| (filehash, <_>::default()))
            .collect::<Result<FileDists, _>>()?;
        let mut broken_backing_virtpys = vec![];

        for virtpy_path in ctx.proj_dirs.virtpys().as_std_path().fs_err_read_dir()? {
            let virtpy_path = virtpy_path?.utf8_path();
            match virtpy_status(&virtpy_path) {
                Ok(_backing) | Err(VirtpyBackingStatus::Orphaned { virtpy: _backing }) => {}
                Err(VirtpyBackingStatus::Broken { .. } | VirtpyBackingStatus::Unlinked) => {
                    broken_backing_virtpys.push(virtpy_path);
                    continue;
                }
                Err(VirtpyBackingStatus::Unknown(_err)) => {
                    // TODO: deal with differently
                    broken_backing_virtpys.push(virtpy_path);
                    continue;
                }
            };
            let Ok(backing) = VirtpyBacking::from_existing(virtpy_path.clone()) else {
                broken_backing_virtpys.push(virtpy_path);
                continue;
            };
            let distributions: HashSet<_> = distributions_used(&backing)
                .collect::<Result<_>>()
                .wrap_err_with(|| {
                    format!(
                        "can't read packages used by {}",
                        virtpy_link_location(&virtpy_path).unwrap_or(virtpy_path)
                    )
                })?;
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
                .records(ctx)?
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

        Ok(StoreDependencies {
            virtpy_dists,
            dist_virtpys,
            dist_files,
            file_dists,
            broken_backing_virtpys,
        })
    }
}

fn package_files(ctx: &Ctx) -> Result<impl Iterator<Item = std::io::Result<FileHash>>> {
    Ok(ctx
        .proj_dirs
        .package_files()
        .as_std_path()
        .fs_err_read_dir()?
        .map_ok(|entry| FileHash::from_filename(&entry.utf8_path())))
}

pub(crate) fn print_verify_store(ctx: &Ctx) -> Result<()> {
    // TODO: if there are errors, link them back to their original distribution
    let mut any_error = false;
    for file in ctx
        .proj_dirs
        .package_files()
        .as_std_path()
        .fs_err_read_dir()?
    {
        if let Err(err) = file
            .map_err(|err| eyre!("failed to read file: {err}"))
            .and_then(|file| file.try_utf8_path())
            .and_then(|path| {
                let hash = FileHash::from_file(&path)?;
                let filename_hash = FileHash::from_filename(&path);
                match hash == filename_hash {
                    true => Ok(()),
                    false => Err(eyre!("doesn't match hash: {path}, hash = {hash}")),
                }
            })
        {
            any_error = true;
            eprintln!("{err}");
        }
    }
    if !any_error {
        println!("everything valid");
    }
    Ok(())
}

pub(crate) fn print_stats(
    ctx: &Ctx,
    human_readable: bool,
    use_binary_si_prefix: bool,
) -> Result<()> {
    let total_size = ctx
        .proj_dirs
        .package_files()
        .as_std_path()
        .fs_err_read_dir()?
        .map(|entry| Ok(entry?.metadata()?.len()))
        .sum::<Result<u64>>()?;

    let deps = StoreDependencies::current(ctx)?;
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
                    match virtpy_link_location(dependent) {
                        Ok(link_location) => {
                            print!("    {link_location}");
                            if ctx.options.verbose >= 3 {
                                print!("  =>  {dependent}");
                            }
                            println!();
                        }
                        Err(err) => {
                            eprintln!("failed to read virpy location for {dependent}: {err}");
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn distributions_used(
    virtpy_dirs: &VirtpyBacking,
) -> impl Iterator<Item = Result<StoredDistribution>> {
    virtpy_dirs
        .dist_infos()
        .filter(|dist_info_path| {
            // The intention is that only we ourselves install packages into
            // our venvs but some other tools may just see the venv structure
            // and place files there themselves.
            // We write to the "INSTALLER" file, but we can't fully rely on that.
            // When poetry installs a package with our poetry plugin, it will use
            // virtpy but it will also overwrite our INSTALLER file with its own
            // if running from inside an active venv. It doesn't do that
            // if the venv is not activated curiously (2023-10-07).
            //
            // poetry also places a dist-info into the venv for the package
            // whose dependencies are managed by poetry.
            // It marks these by writing "poetry" to the *.dist-info/INSTALLER file.
            // Interestingly, wheels installed by poetry contain poetry's version
            // but this one does not.
            //
            // We check for the DISTRIBUTION_HASH file which is something we added ourselves.
            //
            // Ignoring files by other installers also makes it possible for other
            // tools to install distributions into virtpys and have it work transparently,
            // although while losing all of virtpys benefits.
            // TODO: build a way to detect foreign, unwanted packages.
            dist_info_path
                .join("DISTRIBUTION_HASH")
                .try_exists()
                .expect("failed to read DISTRIBUTION_HASH")
            // fs_err::read_to_string(dist_info_path.join("INSTALLER"))
            //     .map_or(true, |installer| installer.trim() == "virtpy")
        })
        .map(stored_distribution_of_installed_dist)
}

pub(crate) fn stored_distribution_of_installed_dist(
    dist_info_path: impl AsRef<Path>,
) -> Result<StoredDistribution> {
    _stored_distribution_of_installed_dist(dist_info_path.as_ref())
}

fn _stored_distribution_of_installed_dist(dist_info_path: &Path) -> Result<StoredDistribution> {
    let hash_path = dist_info_path.join(crate::DIST_HASH_FILE);
    let hash = fs_err::read_to_string(hash_path).wrap_err("failed to get distribution hash")?;
    let (name, version) = package_info_from_dist_info_dirname(dist_info_path.file_name().unwrap());

    Ok(StoredDistribution {
        distribution: Distribution {
            name: name.into(),
            version: version.into(),
            sha: DistributionHash(hash),
        },
    })
}

fn register_distribution_files_of_wheel(
    ctx: &Ctx,
    install_folder: &Path,
    wheel_record: WheelRecord,
    distribution: &Distribution,
    stored_distributions: &mut HashMap<DistributionHash, StoredDistribution>,
) -> Result<()> {
    let stored_distrib = StoredDistribution {
        distribution: distribution.clone(),
    };

    if ctx.options.verbose >= 1 {
        println!(
            "Adding {} {} to central store.",
            distribution.name, distribution.version
        );
    }

    for file in &wheel_record.files {
        let src = install_folder.join(&file.path);
        assert!(src.starts_with(install_folder));
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
pub(crate) struct StoredDistributions<S: Share>(pub(crate) _StoredDistributions, FileLockGuard<S>);

pub(crate) type _StoredDistributions = HashMap<DistributionHash, StoredDistribution>;

impl<S: Share> PartialEq for StoredDistributions<S> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl<S: Share> Eq for StoredDistributions<S> {}

impl StoredDistribution {
    fn record_file(&self, ctx: &Ctx) -> PathBuf {
        ctx.proj_dirs
            .records()
            .join(self.distribution.as_csv())
            .join("RECORD")
    }

    fn dist_info_file(&self, ctx: &Ctx, file: &str) -> Option<PathBuf> {
        let record_path = self.record_file(ctx);
        if file == "RECORD" {
            return Some(record_path);
        }

        // This could be optimized, as it's kinda wasteful to keep rereading this on every call,
        // but it's only called once per package when installing it into
        // a new virtpy right now, so it doesn't matter.
        let path_in_record = PathBuf::from(self.distribution.dist_info_name()).join(file);
        let record = WheelRecord::from_file(record_path).unwrap();
        record
            .files
            .into_iter()
            .find(|entry| entry.path == path_in_record)
            .map(|entry| ctx.proj_dirs.package_file(&entry.hash))
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
        ctx.proj_dirs.records().join(self.distribution.as_csv())
    }

    fn records(&self, ctx: &Ctx) -> Result<impl Iterator<Item = RecordEntry>> {
        let record = self.record_file(ctx);
        Ok(WheelRecord::from_file(record)?.files.into_iter())
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

        let record = WheelRecord::from_file(self.record_file(ctx))?;
        let mut data_exes = record.files;
        let script_path = PathBuf::from(self.distribution.data_dir_name()).join("scripts");
        data_exes.retain(|entry| entry.path.starts_with(&script_path));

        let data_exes = data_exes
            .into_iter()
            .filter_map(|entry| entry.path.file_name().map(|s| s.to_owned()))
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
        Ok(exes)
    }
}

#[derive(Debug)]
pub(crate) struct Shared;

#[derive(Debug)]
pub(crate) struct Exclusive;

pub(crate) trait Share {
    const IS_EXCLUSIVE: bool;
}

impl Share for Shared {
    const IS_EXCLUSIVE: bool = false;
}

impl Share for Exclusive {
    const IS_EXCLUSIVE: bool = true;
}

impl<S: Share> StoredDistributions<S> {
    fn try_load_old(reader: impl std::io::Read) -> Option<_StoredDistributions> {
        let stored_distribs = serde_json::from_reader::<
            _,
            HashMap<String, HashMap<DistributionHash, StoredDistribution>>,
        >(reader)
        .ok()?;

        let mut new_format_stored_distribs = HashMap::<DistributionHash, StoredDistribution>::new();

        for (_python_version, inner) in stored_distribs {
            new_format_stored_distribs.extend(inner);
        }
        Some(new_format_stored_distribs)
    }

    pub(crate) fn load(ctx: &Ctx) -> Result<Self> {
        Self::load_from(ctx.proj_dirs.installed_distributions_log())
    }

    pub(crate) fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        Self::_load_from(path.as_ref())
    }

    fn _load_from(path: &Path) -> Result<Self> {
        let file = fs_err::OpenOptions::new()
            .create(true)
            .read(true)
            // we're actually only reading, but when create(true) is used,
            // the file must be set to write or append
            .write(true)
            .open(path)
            .wrap_err("failed to open stored distributions log")?;

        let mut lock = lock_file(file)?;
        if lock.metadata()?.len() == 0 {
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
}

impl StoredDistributions<Exclusive> {
    fn save(&self) -> Result<()> {
        self._save().wrap_err("failed to save stored distributions")
    }

    fn _save(&self) -> Result<()> {
        let mut file = &self.1.file;
        // Truncate file, then write to it.
        // We mustn't close our filehandle or our lock would be gone with it.
        file.seek(std::io::SeekFrom::Start(0))?;
        file.set_len(0)?;
        serde_json::to_writer_pretty(file, &self.0)?;
        Ok(())
    }
}

fn lock_file<S: Share>(file: fs_err::File) -> Result<FileLockGuard<S>> {
    use fs2::FileExt;
    if S::IS_EXCLUSIVE {
        file.file().lock_exclusive()?;
    } else {
        file.file().lock_shared()?;
    }
    Ok(FileLockGuard {
        file,
        _s: PhantomData,
    })
}

#[derive(Debug)]
struct FileLockGuard<S: Share> {
    file: File,
    _s: PhantomData<S>,
}

impl<S: Share> Drop for FileLockGuard<S> {
    fn drop(&mut self) {
        use fs2::FileExt;
        let _ = self.file.file().unlock();
    }
}

impl<S: Share> std::ops::Deref for FileLockGuard<S> {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl<S: Share> std::ops::DerefMut for FileLockGuard<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

// Usable only for our own installation from wheel files
pub(crate) fn register_new_distribution(
    ctx: &Ctx,
    _: WheelChecked,
    distrib: Distribution,
    install_folder: &Path,
    wheel_record: WheelRecord,
) -> Result<()> {
    if ctx.options.verbose >= 2 {
        println!(
            "    New distribution: {}=={}, {}",
            distrib.name, distrib.version, distrib.sha
        );
    }

    let mut all_stored_distributions = StoredDistributions::<Exclusive>::load(ctx)?;
    register_distribution_files_of_wheel(
        ctx,
        install_folder,
        wheel_record,
        &distrib,
        &mut all_stored_distributions.0,
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

pub(crate) fn wheel_is_already_registered(ctx: &Ctx, distribution: &Distribution) -> Result<bool> {
    let stored_distributions = StoredDistributions::<Shared>::load(ctx)?;
    Ok(stored_distributions.0.contains_key(&distribution.sha))
}

#[cfg(test)]
mod test {
    //use super::*;
}
