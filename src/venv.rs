//! This module deals with the venvs we are creating.
//!
//! Each venv is composed of two pieces
//! 1. The venv anywhere in the file system that a user interacts with
//! 2. The backing venv in a central location to which (1) contains symlinks to

use crate::internal_store::{wheel_is_already_registered, StoredDistributions};
use crate::python::wheel::{
    normalized_distribution_name_for_wheel, CheckStrategy, DistributionMetadata, RecordEntry,
    WheelRecord,
};
use crate::python::{
    generate_executable, records, Distribution, DistributionHash, EntryPoint, FileHash,
    PythonVersion, PythonVersionError,
};
use crate::{
    check_output, ignore_target_doesnt_exist, Ctx, CENTRAL_LOCATION, DEFAULT_VIRTPY_PATH,
    LINK_LOCATION,
};
use crate::{
    check_status, delete_virtpy_backing, dist_info_matches_package, executables_path,
    ignore_target_exists, is_not_found, python_path, relative_path, symlink_dir, symlink_file,
    Path, PathBuf, ShimInfo, StoredDistribution, CENTRAL_METADATA, DIST_HASH_FILE, LINK_METADATA,
};
use crate::{prelude::*, INSTALLER_FILE};
use clap::ValueEnum;
use eyre::{bail, eyre, Context};
use fs_err::PathExt;
use itertools::Itertools;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::io::Write;
use std::path::Path as StdPath;
use std::process::Command;
use tempdir::TempDir;

/// A venv in the central store.
/// When we are installing files into this venv, we hardlink them from the shared storage.
/// The backing virtpys contain no symlinks.
/// It's important that we recreate the full directory structure of what a venv would
/// normally look like without any symlinks, because some python modules introspect their own
/// files and in doing so, they often get the absolute path to their own location via a function
/// that also resolves symlinks like os.path.realpath or pathlib.Path.resolve.
/// They then expect a specific directory structure at the resolved path and go up and
/// down directories. The backing venvs give them this directory structure.
/// The virtpys out in the filesystem that a user is interacting with contain symlinks to the
/// backing venv.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct VirtpyBacking {
    location: PathBuf,
    python_version: PythonVersion,
}

/// A venv anywhere in the filesystem that links to the backing venv.
/// This struct is only constructed if the virtpy is known to be valid at construction time.
/// This doesn't guarantee that it will remain valid for the lifetime of the struct (as other processes can modify the filesystem)
/// but it guarantees that we atleast checked once.
pub(crate) struct Virtpy {
    link: PathBuf,
    backing: PathBuf,
    python_version: PythonVersion,
}

/// Provide accessors to various directories in a venv.
/// Both [`VirtpyBacking`]s and [`Virtpy`]s have the directory structure of a venv,
/// so a lot of the code is shared.
pub(crate) trait VirtpyPaths {
    fn location(&self) -> &Path;
    fn python_version(&self) -> PythonVersion;
    fn metadata_dir(&self) -> PathBuf;

    fn executables(&self) -> PathBuf {
        executables_path(self.location())
    }

    fn python(&self) -> PathBuf {
        python_path(self.location())
    }

    fn dist_info(&self, package: &str) -> Result<PathBuf> {
        let package = &normalized_distribution_name_for_wheel(package);
        self.dist_infos()
            .find(|path| dist_info_matches_package(path, package))
            .ok_or_else(|| eyre!("failed to find dist-info for {package}"))
    }

    fn dist_infos(&self) -> Box<dyn Iterator<Item = PathBuf>> {
        Box::new(
            self.site_packages()
                .read_dir()
                .unwrap()
                .map(Result::unwrap)
                .map(|dir_entry| dir_entry.path())
                .map(<_>::into_utf8_pathbuf)
                .filter(|path| {
                    path.file_name()
                        .map_or(false, |fn_| fn_.ends_with(".dist-info"))
                }),
        )
    }

    fn site_packages(&self) -> PathBuf {
        venv_site_packages(self.location(), self.python_version())
    }

    fn set_metadata(&self, name: &str, value: &str) -> std::io::Result<()> {
        fs_err::write(self.metadata_dir().join(name), value)?;
        Ok(())
    }

    fn get_metadata(&self, name: &str) -> Result<Option<String>> {
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

    fn installed_distributions_metadata(&self) -> Vec<Result<DistributionMetadata>> {
        self.dist_infos()
            .map(|dist_info| {
                let metadata = fs_err::read_to_string(dist_info.join("METADATA"))?;
                DistributionMetadata::from_str(&metadata)
            })
            .collect()
    }
}

fn venv_site_packages(venv: &Path, python_version: PythonVersion) -> PathBuf {
    if cfg!(unix) {
        venv.join(format!(
            "lib/python{}/site-packages",
            python_version.as_string_without_patch()
        ))
    } else {
        venv.join("Lib").join("site-packages")
    }
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

impl VirtpyPaths for Virtpy {
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

trait VirtpyPathsPrivate: VirtpyPaths {
    fn install_paths(&self) -> Result<InstallPaths> {
        // cached so we don't get the >30ms delay from invoking python every time.
        let cache_file = "install_paths.json";
        // TODO: ensure cache is always in same location (only link or only backing)
        if let Some(install_paths) = self
            .get_metadata(cache_file)?
            .and_then(|data| serde_json::from_str(&data).ok())
        {
            return Ok(InstallPaths(install_paths));
        }
        let install_paths = InstallPaths::detect(self.python(), self.python_version());
        if let Some(serialized_paths) = install_paths
            .as_ref()
            .ok()
            .and_then(|paths| serde_json::to_string(&paths.0).ok())
        {
            let _ = self.set_metadata(cache_file, &serialized_paths);
        }
        install_paths
    }
}

impl VirtpyPathsPrivate for VirtpyBacking {}
impl VirtpyPathsPrivate for Virtpy {}

impl VirtpyBacking {
    /// A successful result does not guarantee, that the virtpy is in a good state, only that
    /// the information to construct a VirtpyBacking could be collected.
    pub(crate) fn from_existing(location: PathBuf) -> Result<Self, VirtpyBackingError> {
        Ok(Self {
            python_version: python_version(&location).map_err(|e| VirtpyBackingError::Broken {
                link: None,
                reason: format!("{}", e),
            })?,
            location,
        })
    }
}

impl Virtpy {
    pub(crate) fn create(
        ctx: &Ctx,
        python_path: &Path,
        path: &Path,
        prompt: Option<String>,
        with_pip_shim: Option<ShimInfo>,
        with_package_resources: bool,
        check_strategy: CheckStrategy,
    ) -> Result<Virtpy> {
        let mut rng = rand::thread_rng();

        // Generate a random id for the virtpy.
        // This should only take 1 attempt, but it's theoretically possible
        // for the id to collide with a previous one, so check and retry if that's the case, but not forever.
        let n_max_attempts = 10;
        let random_path_gen = std::iter::repeat_with(|| {
            let id = std::iter::repeat_with(|| rng.sample(rand::distributions::Alphanumeric))
                .take(12)
                .map(|byte| byte as char)
                .collect::<String>();
            ctx.proj_dirs.virtpys().join(id)
        });

        let central_path = random_path_gen
            .take(n_max_attempts)
            .find(|path| !path.exists())
            .ok_or_else(|| {
                eyre!("failed to generate an unused virtpy path in {n_max_attempts} attempts")
            })?;

        let prompt = prompt
            .as_deref()
            .or_else(|| path.file_name())
            .unwrap_or(DEFAULT_VIRTPY_PATH);
        let virtpy = _create_virtpy(
            ctx,
            central_path,
            python_path,
            path,
            prompt,
            with_pip_shim,
            with_package_resources,
        )?;
        virtpy.set_check_strategy(check_strategy)?;
        Ok(virtpy)
    }

    pub(crate) fn from_existing(virtpy_link: &Path) -> Result<Self> {
        virtpy_link_status(virtpy_link)
            .wrap_err_with(|| eyre!("working order `{virtpy_link}` couldn't be verified.",))
    }

    pub(crate) fn add_dependency_from_file(
        &self,
        ctx: &Ctx,
        file: &Path,
        check_strategy: CheckStrategy,
        use_pep517: bool,
    ) -> Result<()> {
        let file_hash = DistributionHash::from_file(file)?;
        let distribution =
            Distribution::from_package_name(file.file_name().unwrap(), file_hash).unwrap();

        if !wheel_is_already_registered(ctx, &distribution)? {
            install_and_register_distribution_from_file(
                ctx,
                file,
                distribution.clone(),
                self.python_version,
                check_strategy,
                use_pep517,
            )?;
        }

        link_distributions_into_virtpy(ctx, self, vec![distribution])
            .wrap_err("failed to add packages to virtpy")
            .map(|e| {
                let _ = fs_err::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(self.metadata_dir().join("installation.log"))
                    .map(|mut f| writeln!(&mut f, "{file}"));
                e
            })
    }

    // TODO: refactor
    pub(crate) fn remove_dependencies(&self, dists_to_remove: HashSet<String>) -> Result<()> {
        let dists_to_remove = dists_to_remove
            .into_iter()
            .map(|name| normalized_distribution_name_for_wheel(&name))
            .collect::<HashSet<_>>();

        let site_packages = self.site_packages();

        let mut dist_infos = vec![];

        // TODO: detect distributions that aren't installed
        for dir_entry in site_packages.as_std_path().fs_err_read_dir()? {
            let dir_entry = dir_entry?;
            // use fs_err::metadata instead of DirEntry::metadata so it traverses symlinks
            // as dist-info dirs were symlinked in when using the old pip install method.
            let filetype = fs_err::metadata(dir_entry.path())?.file_type();
            if !filetype.is_dir() {
                continue;
            }
            let dirname = dir_entry.utf8_file_name();

            if dirname.ends_with(".dist-info") {
                dist_infos.push(dirname);
            }
        }

        dist_infos.retain(|name| {
            let dist = name.split('-').next().unwrap();
            // It should already be in normalized form as far as I know,
            // but of course that's not always the case.
            let dist = normalized_distribution_name_for_wheel(dist);
            dists_to_remove.contains(&dist)
        });

        let mut files_to_remove = vec![];
        for info in dist_infos {
            let dist_infos = site_packages.join(&info);
            let record_file = dist_infos.join("RECORD");

            for file in records(&record_file)? {
                let file = file?;

                let path = site_packages.join(file.path);
                // NO ESCAPE
                if !path.starts_with(self.location()) {
                    continue;
                }

                if path.extension() == Some("py") {
                    files_to_remove.push(path.with_extension("pyc"));
                }
                files_to_remove.push(path);
            }
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

        // add all parent dirs of files to be removed to a list for later deletion
        let mut directories = HashSet::new();
        for path in &files_to_remove {
            let mut path = path.to_owned();
            while path.pop() {
                if path == site_packages {
                    break;
                }
                if !directories.insert(path.clone()) {
                    break;
                }
            }
        }
        let directories = directories
            .into_iter()
            .sorted_by_key(|path| std::cmp::Reverse(path.iter().count()))
            .collect::<Vec<_>>();

        // TODO: if an error occured, don't delete the dist-info, especially not the RECORD
        //       so deletion can retry.
        for path in &files_to_remove {
            assert!(path.starts_with(&site_packages));

            if false {
                if path.extension() != Some("pyc") {
                    println!("deleting {path}");
                }
            } else {
                // not using fs_err here, because we're not bubbling the error up
                if let Err(e) = std::fs::remove_file(path).or_else(ignore_target_doesnt_exist) {
                    eprintln!("failed to delete {path}: {e}");
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

    // Returns the path of the python installation on which this
    // this virtpy builds
    pub(crate) fn global_python(&self) -> Result<PathBuf> {
        if cfg!(unix) {
            let python = self.python();
            let link = &self.link;
            let python = python
                .as_std_path()
                .fs_err_canonicalize()
                .wrap_err_with(|| {
                    eyre!("failed to find path of the global python used by virtpy at {link}")
                })?
                .try_into_utf8_pathbuf()?;
            Ok(python)
        } else {
            let version = python_version(self.location())?;
            crate::python::detection::detect(&version.as_string_without_patch())
        }
    }

    pub(crate) fn pip_shim_log(&self) -> Result<Option<String>> {
        self.get_metadata("pip_shim.log")
    }

    pub(crate) fn delete(self) -> Result<()> {
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

    fn set_has_pip_shim(&self) -> std::io::Result<()> {
        fs_err::write(self._pip_shim_flag_file(), "")
    }

    pub(crate) fn set_check_strategy(&self, strategy: CheckStrategy) -> std::io::Result<()> {
        self.set_metadata(
            "wheel_check_strategy",
            strategy
                .to_possible_value()
                .expect("skipped value")
                .get_name(),
        )
    }
}

/// Both the backing venv and the venv link contain references to the path
/// of the other. Either one could be deleted without the other one
/// and the link could also be moved
#[derive(thiserror::Error, Debug)]
pub(crate) enum VirtpyError {
    #[error("virtpy copied or moved from {should}")]
    WrongLocation {
        should: PathBuf,
        #[allow(unused)]
        actual: PathBuf,
    },
    #[error("backing storage for virtpy missing: {target}")]
    Dangling { target: PathBuf },
    #[error("virtpy is broken: {reason}")]
    Broken {
        backing: Option<PathBuf>,
        reason: String,
    },
    #[error("unknown error: {0}")]
    Unknown(#[from] eyre::Report),
}

fn virtpy_link_status(virtpy_link_path: &Path) -> Result<Virtpy, VirtpyError> {
    let supposed_location = virtpy_link_supposed_location(virtpy_link_path)
        .wrap_err("failed to read original location of virtpy")?;
    if !paths_match(virtpy_link_path.as_ref(), supposed_location.as_ref()).unwrap() {
        return Err(VirtpyError::WrongLocation {
            should: supposed_location,
            actual: virtpy_link_path.to_owned(),
        });
    }

    let target = virtpy_link_target(virtpy_link_path).wrap_err("failed to find virtpy backing")?;
    if !target.exists() {
        return Err(VirtpyError::Dangling { target });
    }

    let python_version = python_version(virtpy_link_path).map_err(|e| {
        let msg = "unable to determine virtpy python version";
        let backing = Some(target.to_owned());
        match e {
            PythonVersionError::VersionKeyMissing | PythonVersionError::UnableToReadVersion(_) => {
                VirtpyError::Broken {
                    backing,
                    reason: format!("{msg}: {e}"),
                }
            }
            PythonVersionError::Unknown(e) => VirtpyError::Unknown(e.wrap_err(msg)),
        }
    })?;

    Ok(Virtpy {
        link: canonicalize(virtpy_link_path)?,
        backing: target,
        python_version,
    })
}

fn link_distributions_into_virtpy(
    ctx: &Ctx,
    virtpy: &Virtpy,
    distributions: Vec<Distribution>,
) -> Result<()> {
    // Link files into the backing virtpy so that when new top-level directories are
    // created, they are guaranteed to be on the same harddrive.
    // Symlinks for the new dirs are generated after all the files have been liked in.
    let site_packages = virtpy.virtpy_backing().site_packages();

    let stored_distributions = StoredDistributions::<crate::internal_store::Shared>::load(ctx)?;
    for distribution in distributions {
        // find compatible hash
        let stored_distrib = match stored_distributions.0.get(&distribution.sha) {
            Some(dists) => dists,
            None => bail!("failed to find distribution in store: {distribution:?}"),
        };

        link_single_requirement_into_virtpy(ctx, virtpy, stored_distrib, &site_packages)?;
    }

    ensure_toplevel_symlinks_exist(&virtpy.backing, virtpy.location())?;

    Ok(())
}

fn link_single_requirement_into_virtpy(
    ctx: &Ctx,
    virtpy: &Virtpy,
    distrib: &StoredDistribution,
    site_packages: &Path,
) -> Result<()> {
    let record_dir = ctx.proj_dirs.records().join(distrib.distribution.as_csv());
    let record_path = record_dir.join("RECORD");

    let mut record = WheelRecord::from_file(record_path)?;

    // Add the distribution's hash to the dist_info first, but add it to the record
    // after the linking has been completed.
    let distrib_dist_info = site_packages.join(distrib.distribution.dist_info_name());
    fs_err::create_dir_all(&distrib_dist_info)?;
    let hash_path = distrib_dist_info.join(DIST_HASH_FILE);
    let dist_hash = &distrib.distribution.sha.0;
    fs_err::write(&hash_path, dist_hash).wrap_err("failed to write distribution hash file")?;

    // Similarly, add the INSTALLER file
    let installer_path = distrib_dist_info.join(INSTALLER_FILE);
    let installer = "virtpy\n";
    fs_err::write(&installer_path, installer).wrap_err("failed to write INSTALLER")?;

    link_files_from_record_into_virtpy(
        ctx,
        &mut record,
        virtpy,
        site_packages,
        &distrib.distribution,
    )?;
    install_executables(ctx, distrib, virtpy, &mut record)?;

    let mut add_entry = |path: &Path, content: &str| -> Result<()> {
        record.files.push(RecordEntry {
            path: relative_path(site_packages, path)?,
            hash: FileHash::from_reader(content.as_bytes()),
            filesize: content.len() as u64,
        });
        Ok(())
    };
    add_entry(&hash_path, dist_hash)?;
    add_entry(&installer_path, installer)?;

    // The RECORD is not linked in, because it doesn't (can't) contain its own hash.
    // Save the (possibly amended) record into the virtpy
    record.save_to_file(
        site_packages
            .join(distrib.distribution.dist_info_name())
            .join("RECORD"),
    )?;
    Ok(())
}

fn link_file_into_virtpy(
    ctx: &Ctx,
    filehash: &FileHash,
    dest: PathBuf,
    distribution: &Distribution,
) {
    let src = ctx.proj_dirs.package_file(filehash);
    fs_err::hard_link(&src, &dest)
        .or_else(|err| {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                // Should this ever happen? No of course not.
                // But pip will happily overwrite things and so we have to as well.
                // Packages that do this for example: jupyter and jupyter_core.
                // TODO: verify file hashes on package removal so we don't delete files that
                //       other packages have already overwritten and which
                //       therefore don't belong to the package that is being removed.
                fs_err::remove_file(&dest)?;
                fs_err::hard_link(&src, &dest)
            } else {
                Err(err)
            }
        })
        .wrap_err_with(|| eyre!("distribution {}", distribution.name_and_version()))
        .unwrap();
}

fn link_files_from_record_into_virtpy(
    ctx: &Ctx,
    record: &mut WheelRecord,
    virtpy: &Virtpy,
    site_packages: &Path,
    distribution: &Distribution,
) -> Result<()> {
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
        fs_err::create_dir_all(dir).unwrap();
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
                record.path = relative_path(site_packages, &dest)?;
                if !is_executable {
                    link_file_into_virtpy(ctx, &record.hash, dest, distribution);
                } else {
                    let src = ctx.proj_dirs.package_file(&record.hash);

                    // First, read the file as bytes to check if it starts with the
                    // magic number, i.e. the shebang "#!python".
                    // Only if it does, read it in as a String.
                    // While the wheel specification only speaks about distributing scripts
                    // (presumably python scripts) in the data directory,
                    // people are also distributing native executables and those are not
                    // UTF-8, so they can't be read into a String.
                    let mut file = fs_err::File::open(&src)?;
                    let mut buf = vec![0; 10];
                    let n_read = file.read(&mut buf)?;
                    let beginning = &buf[..n_read];

                    // A bit complicated because I'm trying to replace ONLY the first line,
                    // indepently of \n and \r\n without running more code than necessary.
                    let shebang_to_replace = b"#!python";
                    if beginning.starts_with(shebang_to_replace) && {
                        let rest = &beginning[shebang_to_replace.len()..];
                        rest.starts_with(b"\r\n") || rest.starts_with(b"\n")
                    } {
                        drop(file);
                        let script = fs_err::read_to_string(src)?;
                        // lines() iter doesn't have a method for getting the rest of the string, sadly.
                        let first_linebreak = script.find('\n'); // could actually be None, for an empty script.
                        let code = first_linebreak.map_or("", |linebreak| &script[linebreak..]);
                        // Rewriting the shebang (or adding a wrapper for windows) changed the hash and filesize
                        *record = generate_executable(
                            &dest,
                            &virtpy.python(),
                            code,
                            &virtpy.site_packages(),
                        )?;
                    } else {
                        link_file_into_virtpy(ctx, &record.hash, dest, distribution);
                    }
                }
            }
            Err(_) => {
                let dest = site_packages.join(&record.path);
                ensure_dir_exists(&dest);
                link_file_into_virtpy(ctx, &record.hash, dest, distribution);
            }
        };
    }

    Ok(())
}

fn ensure_toplevel_symlinks_exist(backing_location: &Path, virtpy_location: &Path) -> Result<()> {
    for entry in backing_location.read_dir()? {
        let entry = entry?;
        let entry_path = entry.utf8_path();
        let entry_name = entry.utf8_file_name();

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
                "virtpy backing contains file that's neither directory nor file: {entry_path}"
            )
        };
        res.or_else(ignore_target_exists)?;
    }
    Ok(())
}

fn _create_virtpy(
    ctx: &Ctx,
    central_path: PathBuf,
    python_path: &Path,
    path: &Path,
    prompt: &str,
    with_pip_shim: Option<ShimInfo>,
    with_package_resources: bool,
) -> Result<Virtpy> {
    _create_bare_venv(python_path, &central_path, prompt)?;

    fs_err::create_dir(path)?;
    let path = canonicalize(path)?;
    ensure_toplevel_symlinks_exist(&central_path, &path)?;

    let abs_path = path
        .as_std_path()
        .fs_err_canonicalize()?
        .try_into_utf8_pathbuf()?;
    {
        let metadata_dir = central_path.join(CENTRAL_METADATA);
        // metadata dir already created, no need to it again.
        fs_err::write(metadata_dir.join(LINK_LOCATION), abs_path.as_str())?;
    }

    {
        let link_metadata_dir = path.join(LINK_METADATA);
        fs_err::create_dir(&link_metadata_dir)?;
        fs_err::write(link_metadata_dir.join(LINK_LOCATION), abs_path.as_str())?;

        debug_assert!(central_path.is_absolute());
        fs_err::write(
            link_metadata_dir.join(CENTRAL_LOCATION),
            central_path.as_str(),
        )?;
    }

    let checked_virtpy = Virtpy {
        // Not all users of this function may need the python version, but it's
        // cheap to get and simpler to just always query.
        // Could be easily replaced with a token-struct that could be converted
        // to a full Virtpy on demand.
        python_version: python_version(&central_path)?,
        link: path,
        backing: central_path,
    };
    if let Some(shim_info) = with_pip_shim {
        add_pip_shim(&checked_virtpy, shim_info).wrap_err("failed to add pip shim")?;
    }
    if with_package_resources {
        add_package_resources(ctx, &checked_virtpy)?;
    }

    Ok(checked_virtpy)
}

fn _create_bare_venv(python_path: &Path, path: &Path, prompt: &str) -> Result<()> {
    // create directory and central metadata directory first. The deletion checks for the presence
    // of this folder as a security precaution and this way it is highly unlikely to fail to be created.
    fs_err::create_dir_all(path.join(CENTRAL_METADATA))?;
    check_status(
        Command::new(python_path)
            .args(["-m", "venv", "--without-pip", "--prompt", prompt])
            .arg(path)
            .stdout(std::process::Stdio::null()),
    )
    .map(drop)
    .wrap_err_with(|| eyre!("failed to create virtpy {path}"))
}

fn install_executables(
    ctx: &Ctx,
    stored_distrib: &StoredDistribution,
    virtpy: &Virtpy,
    wheel_record: &mut WheelRecord,
) -> Result<(), color_eyre::Report> {
    let entrypoints = stored_distrib.entrypoints(ctx).unwrap_or_default();
    for entrypoint in entrypoints {
        let executables_path = virtpy.executables();
        let err = || eyre!("failed to install executable {}", entrypoint.name);
        let python_path = executables_path.join("python");
        let record_entry = entrypoint
            .generate_executable(&executables_path, &python_path, &virtpy.site_packages())
            .wrap_err_with(err)?;
        wheel_record.files.push(record_entry);
    }
    Ok(())
}

fn add_pip_shim(virtpy: &Virtpy, shim_info: ShimInfo<'_>) -> Result<()> {
    let target_path = virtpy.site_packages().join("pip");
    let shim_zip = include_bytes!("../pip_shim/pip_shim.zip");
    let mut archive = zip::read::ZipArchive::new(std::io::Cursor::new(shim_zip))
        .wrap_err("internal error: invalid archive for pip shim")?;
    archive
        .extract(&target_path)
        .wrap_err_with(|| eyre!("failed to extract pip shim archive to {target_path}"))?;

    let entry_point = EntryPoint {
        name: "pip".to_owned(),
        module: "pip".to_owned(),
        qualname: "main".to_owned(),
    };
    let _ = entry_point.generate_executable(
        &virtpy.executables(),
        &virtpy.python(),
        &virtpy.site_packages(),
    )?;
    virtpy.set_has_pip_shim()?;
    virtpy.set_metadata("virtpy_exe", shim_info.virtpy_exe.as_str())?;
    virtpy.set_metadata("proj_dir", shim_info.proj_dirs.data().as_str())?;

    Ok(())
}

pub(crate) fn virtpy_link_location(virtpy: &Path) -> std::io::Result<PathBuf> {
    let backlink = virtpy.join(CENTRAL_METADATA).join(LINK_LOCATION);
    fs_err::read_to_string(backlink).map(PathBuf::from)
}

pub(crate) fn virtpy_link_target(virtpy_link: &Path) -> std::io::Result<PathBuf> {
    let link = virtpy_link.join(LINK_METADATA).join(CENTRAL_LOCATION);
    fs_err::read_to_string(link).map(PathBuf::from)
}

fn virtpy_link_supposed_location(virtpy_link: &Path) -> std::io::Result<PathBuf> {
    let link = virtpy_link.join(LINK_METADATA).join(LINK_LOCATION);
    fs_err::read_to_string(link).map(PathBuf::from)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum VirtpyBackingStatus {
    #[error("the virtpy linked to this backing not found")]
    Orphaned { virtpy: VirtpyBacking },
    // NOTE: it may be better to roll Unlinked into Broken
    #[error("the link_location file is missing")]
    Unlinked,
    #[error("virtpy is unusable, an important invariant was broken: {reason}")]
    Broken { link: PathBuf, reason: String },
    #[error(transparent)]
    Unknown(#[from] eyre::Report),
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum VirtpyBackingError {
    // #[error("the virtpy linking to this backing could not be found: {link}")]
    // Orphaned { link: PathBuf },
    #[error("virtpy is unusable, an important invariant was broken: {reason}")]
    Broken {
        link: Option<PathBuf>,
        reason: String,
    },
    // TODO: map this onto Broken or Other, but maintain the backtrace
    // #[error(transparent)]
    // PythonVersion(#[from] PythonVersionError),
    // #[error(transparent)]
    // Other(#[from] eyre::Report),
}

pub(crate) fn virtpy_status(virtpy_path: &Path) -> Result<VirtpyBacking, VirtpyBackingStatus> {
    let link_location = match virtpy_link_location(virtpy_path) {
        Ok(location) => location,
        Err(err) if is_not_found(&err) => {
            return Err(VirtpyBackingStatus::Unlinked {});
        }
        Err(err) => Err(err).wrap_err("failed to read location of corresponding virtpy")?,
    };

    let python_version = python_version(virtpy_path).map_err(|e| {
        let msg = "unable to determine virtpy python version";
        match e {
            PythonVersionError::Unknown(e) => VirtpyBackingStatus::Unknown(e.wrap_err(msg)),
            e => VirtpyBackingStatus::Broken {
                link: link_location.to_owned(),
                reason: format!("{msg}: {e}"),
            },
        }
    })?;

    for expected_path in ["include", "lib", "lib64", "pyvenv.cfg"]
        .into_iter()
        .map(|p| virtpy_path.join(p))
        .chain(std::iter::once(executables_path(virtpy_path)))
    {
        if !expected_path.exists() {
            let filename = expected_path.file_name().unwrap();
            return Err(VirtpyBackingStatus::Broken {
                link: link_location,
                reason: format!("Missing file: {filename}"),
            });
        }
    }

    let link_target = virtpy_link_target(&link_location);

    let backing = VirtpyBacking {
        location: virtpy_path.to_owned(),
        python_version,
    };

    if let Err(err) = &link_target {
        if is_not_found(err) {
            return Err(VirtpyBackingStatus::Orphaned { virtpy: backing });
        }
    }

    let link_target = link_target
        .map(PathBuf::from)
        .wrap_err("failed to read virtpy link target through backlink")?;

    if !paths_match(virtpy_path.as_ref(), link_target.as_ref()).unwrap() {
        return Err(VirtpyBackingStatus::Orphaned { virtpy: backing });
    }

    // for entry in link_location.read_dir()? {
    //     let entry = entry?;
    //     // any standard paths are utf8
    //     let Ok(path) = entry.try_utf8_path() else {
    //         continue;
    //     };
    //     if !path.exists() {
    //         return Ok(Err(VirtpyBackingError::Broken {
    //             link: Some(link_location),
    //             reason: format!("symlink target missing: {path}"),
    //         }));
    //     }
    // }

    Ok(backing)
}

/// The paths where the contents of subdirs of a wheel's data directory should be placed.
/// The documentation does not say what these are or where to get them, but it says that it follows
/// distutils.commands.install.install and we can seemingly extract them from there.
/// Is this correct? Who knows with "standards" like in the python world.
///
/// With Python3.12, the wheel specification now claims that sysconfig defines these paths.
/// That is certainly more convenient, given that there's sysconfig.get_paths("venv"), which returns
/// a dict of the paths or sysconfig.get_path(pathname, scheme) for a single path, but there's
/// no "header" path.
/// There is "include" and "platinclude", neither of which are confined to the venv like "headers"
/// was with distutils.
///
/// This is a mapping like `{ "headers": "some/path/to/place/headers", "purelib": "other/path" }`.
struct InstallPaths(HashMap<String, PathBuf>);

impl InstallPaths {
    /// Since 3.12, Python no longer contains the distutils module in the stdlib.
    /// From python3.11 onwards, the sysconfig module contains an installation scheme for venv.
    /// Unlike in other schemes, this one will not point outside the venv for some of the paths.
    /// It is not a full replacement for distutils' install schemes, because it doesn't have
    /// a "headers" install path. It has "include" and "platinclude" but both of those
    /// will (may?) point outside the venv.
    fn detect(python_path: impl AsRef<Path>, version: PythonVersion) -> Result<Self> {
        if version
            < (PythonVersion {
                major: 3,
                minor: 12,
                patch: 0,
            })
        {
            return Self::detect_legacy(python_path.as_ref());
        }

        let get_paths = r#"import json
import sysconfig
paths = sysconfig.get_paths("venv")
print(json.dumps(paths))
"#;

        let output = check_output(Command::new(python_path.as_ref()).args(["-c", get_paths]))?;
        let mut paths: HashMap<String, PathBuf> = serde_json::from_str(&output)?;
        paths.retain(|key, _| {
            ["purelib", "platlib", "headers", "scripts", "data"].contains(&key.as_str())
        });

        // The condition is always true as of 3.12. It might change in the future, but it probably won't.
        if !paths.contains_key("headers") {
            if let Some(venv_root) = paths.get("data").map(|p| p.to_owned()) {
                // For comparison, pip is also adding "headers" to the scheme after querying distutils.
                // https://github.com/pypa/pip/blob/af0087094e1a84552f180e011ad298ab1a725fa0/src/pip/_internal/locations/_distutils.py#L100
                //
                // I don't know why they vendor distutils, but then also define "headers" themselves afterwards.
                // pip differs from distutils in that it includes a directory named "site" below "include" and above
                // "python3.XX".
                // With all of these path variations, how do C builds ever find their headers?
                paths.insert(
                    "headers".to_owned(),
                    venv_root
                        .join("include")
                        .join(format!("python{}", version.as_string_without_patch()))
                        // The final path component "venv" here is the scheme name.
                        // I don't understand the point of that. It seems counterproductive to finding
                        // headers, but distutils is also including that.
                        .join("venv"),
                );
            }
        }

        Ok(InstallPaths(paths))
    }

    fn detect_legacy(python_path: impl AsRef<Path>) -> Result<Self> {
        let get_paths = |sys_name| {
            format!(
                r#"import json
from distutils import dist
from distutils.command import install

distrib = dist.Distribution({{"name": "{sys_name}"}})
inst = install.install(distrib)
inst.finalize_options()

paths = {{
    k: getattr(inst, f"install_{{k}}") for k in install.SCHEME_KEYS
}}
print(json.dumps(paths))"#
            )
        };

        let get_paths = if cfg!(unix) {
            get_paths("unix_prefix")
        } else {
            // TODO: check that this is correct
            get_paths("nt")
        };

        let output = check_output(Command::new(python_path.as_ref()).args(["-c", &get_paths]))?;

        Ok(InstallPaths(serde_json::from_str(&output)?))
    }
}

fn install_and_register_distribution_from_file(
    ctx: &Ctx,
    distrib_path: &Path,
    distribution: Distribution,
    python_version: crate::python::PythonVersion,
    check_strategy: CheckStrategy,
    use_pep517: bool,
) -> Result<()> {
    let tmp_dir = tempdir::TempDir::new_in(ctx.proj_dirs.tmp(), "virtpy_wheel")?;
    let (distrib_path, _wheel_tmp_dir) = match distrib_path.extension().unwrap() {
        "whl" => (distrib_path.to_owned(), None),
        _ => {
            if ctx.options.verbose >= 2 {
                println!("converting to wheel: {distrib_path}");
            }

            let python = crate::python::detection::detect_from_version(python_version)?;
            let (wheel_path, tmp_dir) =
                crate::python::convert_to_wheel(ctx, &python, distrib_path, use_pep517)?;

            if ctx.options.verbose >= 2 {
                println!("wheel file placed at {wheel_path}");
            }

            (wheel_path, Some(tmp_dir))
        }
    };
    assert!(distrib_path.extension().unwrap() == "whl");
    crate::python::wheel::unpack_wheel(&distrib_path, tmp_dir.path())?;

    let install_folder = tmp_dir.utf8_path();
    let src_dist_info = install_folder.join(distribution.dist_info_name());
    let mut wheel_record = WheelRecord::from_file(src_dist_info.join("RECORD"))
        .wrap_err("couldn't get dist-info/RECORD")?;

    let wheel_checked = crate::python::wheel::verify_wheel_contents_or_repair(
        install_folder,
        &distribution,
        &mut wheel_record,
        check_strategy,
    )?;

    crate::internal_store::register_new_distribution(
        ctx,
        wheel_checked,
        distribution,
        install_folder,
        wheel_record,
    )?;

    Ok(())
}

// Returns path of pkg_resources wheel.
// Generates the wheel, if it isn't cached already.
fn package_resources_wheel(ctx: &Ctx, global_python: &Path) -> Result<PathBuf> {
    let wheel_dir = ctx.proj_dirs.data().join("wheels");
    match find_wheel(&wheel_dir)? {
        Some(path) => Ok(path),
        None => generate_pkg_resources_wheel(ctx, global_python, wheel_dir),
    }
}

// Generate pkg_resources wheel and store it in our data directory for later use.
fn generate_pkg_resources_wheel(
    ctx: &Ctx,
    global_python: &camino::Utf8Path,
    wheel_dir: camino::Utf8PathBuf,
) -> Result<PathBuf> {
    // Create a venv WITH pip. This will also install setuptools and pkg_resources.
    // We can extract the pkg_resources module and generate a wheel from it.
    // clean it up by deleting all the python-specific pyc files
    // and removing them from the RECORD, then pack the module into a wheel.
    // We can then use the wheel to install it into virtpys just like a normal package.
    // The pkg_resources RECORD file doesn't conform to the spec (of course).
    // It is missing hashes and filesizes for *.pyc files, so we need to filter those
    // out before even constructing the WheelRecord.
    fs_err::create_dir_all(&wheel_dir)?;
    let tmp_dir = tempdir::TempDir::new_in(ctx.proj_dirs.tmp(), "generate_pkg_resources_whl")?;
    let venv_dir = tmp_dir.try_utf8_path()?.join(".venv");
    check_status(
        Command::new(global_python)
            .args(["-m", "venv"])
            .arg(&venv_dir)
            .stdout(std::process::Stdio::null()),
    )?;
    let python_version = python_version(&venv_dir)?;
    let site_packages = venv_site_packages(&venv_dir, python_version);

    // old
    //pack_pkg_resources_wheel(&tmp_dir, &site_packages, global_python)?;

    // new
    create_pkg_resources_wheel(&tmp_dir, &site_packages, global_python)?;

    let tmp_dir_path = tmp_dir.try_utf8_path()?;
    let wheel_path =
        find_wheel(tmp_dir_path)?.ok_or_else(|| eyre!("no pkg_resources wheel generated"))?;
    let wheel_name = wheel_path.file_name().unwrap();

    let target = wheel_dir.join(wheel_name);

    fs_err::rename(tmp_dir.path().join(wheel_name), &target)
        // If another process already placed it there in the meantime, that's fine too
        .or_else(ignore_target_exists)?;
    Ok(target)
}

fn find_wheel(dir: &Path) -> Result<Option<PathBuf>> {
    glob::glob(&format!("{dir}/*.whl"))?
        .next()
        .map(|res| res?.try_into_utf8_pathbuf())
        .transpose()
}

// Generate a wheel from just the pkg_resources directory. This ignores
// a dist-info directory, if it exists. That also means it works without needing one
// and python3.10 on Ubuntu 22.04 doesn't create a dist-info directory.
fn create_pkg_resources_wheel(
    tmp_dir: &TempDir,
    site_packages: &Path,
    global_python: &Path,
) -> Result<()> {
    fs_err::rename(
        site_packages.join("pkg_resources"),
        tmp_dir.path().join("pkg_resources"),
    )?;
    // Create a setup.py to describe the package.
    // This or some other config describing the build is required for `pip wheel`.
    //
    // setup.py is considered a legacy tool to define the build process
    // but the new one (pyproject.toml) isn't supported in setuptools yet.
    // Support was added in setuptools v61, but it's still experimental and
    // the latest version of setuptools in the latest version of Ubuntu for
    // python3.10 is even older (v59) as of 2022-05-09.
    // We could possibly define a setup.cfg as well, but that is also a legacy
    // tool now, just a newer one.
    // setup.py is still common enough that it will likely continue to work
    // for a long time.
    fs_err::write(
        tmp_dir.path().join("setup.py"),
        r#"from setuptools import setup, find_packages

setup(
    name = "pkg_resources",
    version = "0.0.0",
    packages = find_packages(),
)
"#,
    )?;
    check_output(
        Command::new(global_python)
            .args(["-m", "pip", "wheel"])
            .arg(tmp_dir.path())
            .arg("--wheel-dir")
            .arg(tmp_dir.path()),
    )?;

    Ok(())
}

// // Try to package the pkg_resources module using the wheel package.
// // Requires that the pkg_resources has been installed as a valid wheel, i.e. there
// // needs to be dist-info directory with the necessary data.
// // This is the case in older python versions but not in newer ones.
// fn pack_pkg_resources_wheel(
//     tmp_dir: &TempDir,
//     site_packages: &Path,
//     global_python: &Path,
// ) -> Result<()> {
//     let pack_dir = tmp_dir.path().join("packme");
//     fs_err::create_dir_all(&pack_dir)?;
//     for dir in ["pkg_resources", "pkg_resources-0.0.0.dist-info"] {
//         fs_err::rename(site_packages.join(dir), pack_dir.join(dir))?;
//     }

//     for entry in walkdir::WalkDir::new(&pack_dir).contents_first(true) {
//         let entry = entry?;
//         let path = entry.path();
//         if entry.file_type().is_file() {
//             if path.extension() == Some("pyc".as_ref()) {
//                 fs_err::remove_file(path)?;
//             }
//         } else if entry.file_type().is_dir() {
//             if path.ends_with("__pycache__") {
//                 // they must be empty by now
//                 fs_err::remove_dir(path)?;
//             }
//         }
//     }

//     let record_path = PathBuf::try_from(
//         pack_dir
//             .join("pkg_resources-0.0.0.dist-info")
//             .join("RECORD"),
//     )?;
//     let record = WheelRecord::from_file_ignoring_pyc(&record_path)?;
//     record.save_to_file(&record_path)?;

//     check_status(
//         Command::new(global_python)
//             .args(&["-m", "wheel", "pack"])
//             .arg(pack_dir)
//             .arg("--dest-dir")
//             .arg(tmp_dir.path()),
//     )?;
//     Ok(())
// }

pub(crate) fn python_version(venv: &Path) -> Result<PythonVersion, PythonVersionError> {
    let mut ini = configparser::ini::Ini::new();
    ini.load(venv.join("pyvenv.cfg"))
        .map_err(|err_string| eyre!("couldn't load pyvenv.cfg for venv at {venv}: {err_string}"))?;

    ini.get("default", "version")
        .ok_or_else(|| PythonVersionError::VersionKeyMissing)
        .and_then(|version| {
            let (_, major, minor, patch) =
                lazy_regex::regex_captures!(r"(\d+)\.(\d+)\.(\d+)", &version)
                    .ok_or_else(|| PythonVersionError::UnableToReadVersion(version.to_owned()))?;

            let parse_num = |num: &str| {
                num.parse::<u32>()
                    .map_err(|_| PythonVersionError::UnableToReadVersion(version.to_owned()))
            };
            Ok(PythonVersion {
                major: parse_num(major)?,
                minor: parse_num(minor)?,
                patch: parse_num(patch)?,
            })
        })
}

fn add_package_resources(ctx: &Ctx, virtpy: &Virtpy) -> Result<()> {
    let pkg_res_wheel = package_resources_wheel(ctx, &virtpy.global_python()?)?;
    virtpy.add_dependency_from_file(ctx, &pkg_res_wheel, CheckStrategy::Repair, false)
}

fn canonicalize(path: &Path) -> Result<PathBuf> {
    Ok(PathBuf::try_from(
        path.as_std_path().fs_err_canonicalize()?,
    )?)
}

fn paths_match(virtpy: &StdPath, link_target: &StdPath) -> Result<bool> {
    Ok(virtpy.fs_err_canonicalize()? == link_target.fs_err_canonicalize()?)
}

#[cfg(test)]
mod test {
    use camino::Utf8PathBuf;

    use super::*;
    use crate::{python::detection::detect, test::test_ctx};

    #[test]
    fn get_install_paths() -> Result<()> {
        let ctx = test_ctx();
        let tmp_dir = tempdir::TempDir::new("virtpy_test")?;
        let virtpy_path: Utf8PathBuf = tmp_dir.path().join("install_paths_test").try_into()?;
        let virtpy = Virtpy::create(
            &ctx,
            &detect("3")?,
            &virtpy_path,
            None,
            None,
            false,
            CheckStrategy::RejectInvalid,
        )?;
        let install_paths = virtpy.install_paths()?;
        let required_keys = ["purelib", "platlib", "headers", "scripts", "data"]
            .iter()
            .map(<_>::to_string)
            .collect::<HashSet<_>>();
        let existent_keys = install_paths.0.keys().cloned().collect::<HashSet<_>>();

        let missing = required_keys.difference(&existent_keys).collect::<Vec<_>>();
        assert!(missing.is_empty(), "missing keys: {missing:?}");
        Ok(())
    }
}
