//! This module deals with the venvs we are creating.
//!
//! Each venv is composed of two pieces
//! 1. The venv anywhere in the file system that a user interacts with
//! 2. The backing venv in a central location to which (1) contains symlinks to

use crate::internal_store::{
    new_dependencies, register_new_distributions, wheel_is_already_registered, StoredDistributions,
};
use crate::python::wheel::{
    is_path_of_executable, normalized_distribution_name_for_wheel, RecordEntry, WheelRecord,
};
use crate::python::{
    generate_executable, print_error_missing_file_in_record, python_version, records,
    serialize_requirements_txt, Distribution, DistributionHash, EntryPoint, FileHash,
    PythonVersion,
};
use crate::{check_output, ignore_target_doesnt_exist, DEFAULT_VIRTPY_PATH};
use crate::{
    check_status, delete_virtpy_backing, dist_info_matches_package, executables_path,
    ignore_target_exists, is_not_found, python::requirements::Requirement, python_path,
    relative_path, remove_leading_parent_dirs, symlink_dir, symlink_file, EResult, Options, Path,
    PathBuf, ProjectDirs, ShimInfo, StoredDistribution, StoredDistributionType, CENTRAL_METADATA,
    DIST_HASH_FILE, INVALID_UTF8_PATH, LINK_METADATA,
};
use eyre::{eyre, Context};
use fs_err::PathExt;
use itertools::Itertools;
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::path::Path as StdPath;

/// A venv in the central store
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
    fn install_paths(&self) -> EResult<InstallPaths> {
        InstallPaths::detect(self.python())
    }
}

impl VirtpyPathsPrivate for VirtpyBacking {}
impl VirtpyPathsPrivate for Virtpy {}

impl VirtpyBacking {
    pub(crate) fn from_existing(location: PathBuf) -> Self {
        Self {
            python_version: python_version(&python_path(&location)).unwrap(),
            location,
        }
    }
}

impl Virtpy {
    pub(crate) fn create(
        project_dirs: &ProjectDirs,
        python_path: &Path,
        path: &Path,
        prompt: Option<String>,
        with_pip_shim: Option<ShimInfo>,
    ) -> EResult<Virtpy> {
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
            .or_else(|| path.file_name())
            .unwrap_or(DEFAULT_VIRTPY_PATH);
        _create_virtpy(central_path, python_path, path, prompt, with_pip_shim)
    }

    pub(crate) fn from_existing(virtpy_link: &Path) -> EResult<Self> {
        match virtpy_link_status(virtpy_link).wrap_err("failed to verify virtpy")? {
            VirtpyStatus::WrongLocation { should, .. } => {
                Err(eyre!("virtpy copied or moved from {}", should))
            }
            VirtpyStatus::Dangling { target } => {
                Err(eyre!("backing storage for virtpy not found: {}", target))
            }
            VirtpyStatus::Ok { matching_virtpy } => Ok(Virtpy {
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

    pub(crate) fn add_dependencies(
        &self,
        proj_dirs: &ProjectDirs,
        requirements: Vec<Requirement>,
        options: Options,
    ) -> EResult<()> {
        let new_deps = new_dependencies(&requirements, proj_dirs, self.python_version)?;

        // The virtpy doesn't contain pip so get the appropriate global python
        let python_path = self.global_python()?;

        install_and_register_distributions(
            &python_path,
            proj_dirs,
            &new_deps,
            self.python_version,
            options,
        )?;

        link_requirements_into_virtpy(proj_dirs, self, requirements, options)
            .wrap_err("failed to add packages to virtpy")
    }

    pub(crate) fn add_dependency_from_file(
        &self,
        proj_dirs: &ProjectDirs,
        file: &Path,
        options: Options,
    ) -> EResult<()> {
        let file_hash = DistributionHash::from_file(file);
        let requirement =
            Requirement::from_filename(file.file_name().unwrap(), file_hash.clone()).unwrap();

        if !wheel_is_already_registered(file_hash, proj_dirs, self.python_version)? {
            install_and_register_distribution_from_file(
                proj_dirs,
                file,
                requirement.clone(),
                self.python_version,
                options,
            )?;
        }

        link_requirements_into_virtpy(proj_dirs, self, vec![requirement], options)
            .wrap_err("failed to add packages to virtpy")
    }

    // TODO: refactor
    pub(crate) fn remove_dependencies(&self, dists_to_remove: HashSet<String>) -> EResult<()> {
        let dists_to_remove = dists_to_remove
            .into_iter()
            .map(|name| normalized_distribution_name_for_wheel(&name))
            .collect::<HashSet<_>>();

        let site_packages = self.site_packages();

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
            let dist = name.split('-').next().unwrap();
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
                if !path.starts_with(self.location()) {
                    continue;
                }

                if path.extension() == Some("py") {
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
                if path.extension() != Some("pyc") {
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
            python::detection::detect(&version.as_string_without_patch())
        }
    }

    pub(crate) fn delete(self) -> EResult<()> {
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

/// Both the backing venv and the venv link contain references to the path
/// of the other. Either one could be deleted without the other one
/// and the link could also be moved
enum VirtpyStatus {
    Ok {
        matching_virtpy: PathBuf,
    },
    WrongLocation {
        should: PathBuf,
        #[allow(unused)]
        actual: PathBuf,
    },
    Dangling {
        target: PathBuf,
    },
}

fn virtpy_link_status(virtpy_link_path: &Path) -> EResult<VirtpyStatus> {
    let supposed_location = virtpy_link_supposed_location(virtpy_link_path)
        .wrap_err("failed to read original location of virtpy")?;
    if !paths_match(virtpy_link_path.as_ref(), supposed_location.as_ref()).unwrap() {
        return Ok(VirtpyStatus::WrongLocation {
            should: supposed_location,
            actual: virtpy_link_path.to_owned(),
        });
    }

    let target = virtpy_link_target(virtpy_link_path).wrap_err("failed to find virtpy backing")?;
    if !target.exists() {
        return Ok(VirtpyStatus::Dangling { target });
    }

    Ok(VirtpyStatus::Ok {
        matching_virtpy: target,
    })
}

fn link_requirements_into_virtpy(
    proj_dirs: &ProjectDirs,
    virtpy: &Virtpy,
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
            .find_map(|hash| existing_deps.get(hash))
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
            stored_distrib,
            &site_packages,
        )?;
    }

    ensure_toplevel_symlinks_exist(&virtpy.backing, virtpy.location())?;

    Ok(())
}

fn link_single_requirement_into_virtpy(
    proj_dirs: &ProjectDirs,
    virtpy: &Virtpy,
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
                site_packages,
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
                site_packages,
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
    virtpy: &Virtpy,
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
        Err(err) if is_not_found(&err) => print_error_missing_file_in_record(distribution, &src),
        Err(err) => panic!("failed to hardlink file from {} to {}: {}", src, dest, err),
    };
}

fn link_files_from_record_into_virtpy_new(
    record: &mut WheelRecord,
    virtpy: &Virtpy,
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
                record.path = relative_path(site_packages, &dest);
                if !is_executable {
                    link_file_into_virtpy(proj_dirs, record, dest, distribution);
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
                            code,
                            &virtpy.site_packages(),
                        )?;
                    } else {
                        link_file_into_virtpy(proj_dirs, record, dest, distribution);
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

fn _create_virtpy(
    central_path: PathBuf,
    python_path: &Path,
    path: &Path,
    prompt: &str,
    with_pip_shim: Option<ShimInfo>,
) -> EResult<Virtpy> {
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

    let checked_virtpy = Virtpy {
        link: path.to_owned(),
        backing: central_path,
        // Not all users of this function may need the python version, but it's
        // cheap to get and simpler to just always query.
        // Could be easily replaced with a token-struct that could be converted
        // to a full Virtpy on demand.
        python_version: python_version(python_path)?,
    };
    if let Some(shim_info) = with_pip_shim {
        add_pip_shim(&checked_virtpy, shim_info).wrap_err("failed to add pip shim")?;
    }

    Ok(checked_virtpy)
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

fn install_executables(
    stored_distrib: &StoredDistribution,
    virtpy: &Virtpy,
    proj_dirs: &ProjectDirs,
    mut wheel_record: Option<&mut WheelRecord>, // only record when unpacking wheels ourselves
) -> Result<(), color_eyre::Report> {
    let entrypoints = stored_distrib.entrypoints(proj_dirs).unwrap_or_default();
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

fn add_pip_shim(virtpy: &Virtpy, shim_info: ShimInfo<'_>) -> EResult<()> {
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

pub(crate) fn virtpy_link_location(virtpy: &Path) -> std::io::Result<PathBuf> {
    let backlink = virtpy.join(CENTRAL_METADATA).join("link_location");
    fs_err::read_to_string(backlink).map(PathBuf::from)
}

pub(crate) fn virtpy_link_target(virtpy_link: &Path) -> std::io::Result<PathBuf> {
    let link = virtpy_link.join(LINK_METADATA).join("central_location");
    fs_err::read_to_string(link).map(PathBuf::from)
}

fn virtpy_link_supposed_location(virtpy_link: &Path) -> std::io::Result<PathBuf> {
    let link = virtpy_link.join(LINK_METADATA).join("link_location");
    fs_err::read_to_string(link).map(PathBuf::from)
}

#[derive(Debug)]
pub(crate) enum VirtpyBackingStatus {
    Ok { matching_link: PathBuf },
    Orphaned { link: PathBuf },
}

pub(crate) fn virtpy_status(virtpy_path: &Path) -> EResult<VirtpyBackingStatus> {
    let link_location = virtpy_link_location(virtpy_path)
        .wrap_err("failed to read location of corresponding virtpy")?;

    let link_target = virtpy_link_target(&link_location);

    if let Err(err) = &link_target {
        if is_not_found(err) {
            return Ok(VirtpyBackingStatus::Orphaned {
                link: link_location,
            });
        }
    }

    let link_target = link_target
        .map(PathBuf::from)
        .wrap_err("failed to read virtpy link target through backlink")?;

    if !paths_match(virtpy_path.as_ref(), link_target.as_ref()).unwrap() {
        return Ok(VirtpyBackingStatus::Orphaned {
            link: link_location,
        });
    }

    Ok(VirtpyBackingStatus::Ok {
        matching_link: link_location,
    })
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

fn install_and_register_distribution_from_file(
    proj_dirs: &ProjectDirs,
    distrib_path: &Path,
    requirement: Requirement,
    python_version: crate::python::PythonVersion,
    options: Options,
) -> EResult<()> {
    let tmp_dir = tempdir::TempDir::new_in(proj_dirs.tmp(), "virtpy_wheel")?;
    let (distrib_path, _wheel_tmp_dir) = match distrib_path.extension().unwrap() {
        "whl" => (distrib_path.to_owned(), None),
        _ => {
            let python = crate::python::detection::detect_from_version(python_version)?;
            let (wheel_path, tmp_dir) =
                crate::python::convert_to_wheel(&python, proj_dirs, distrib_path)?;
            (wheel_path, Some(tmp_dir))
        }
    };
    assert!(distrib_path.extension().unwrap() == "whl");
    crate::python::wheel::unpack_wheel(&distrib_path, tmp_dir.path())?;

    let distrib = crate::python::Distribution {
        name: requirement.name,
        version: requirement.version,
        sha: requirement.available_hashes.into_iter().next().unwrap(),
    };

    crate::internal_store::register_new_distribution(
        options,
        distrib,
        proj_dirs,
        python_version,
        tmp_dir,
    )?;

    Ok(())
}

fn canonicalize(path: &Path) -> EResult<PathBuf> {
    Ok(PathBuf::try_from(
        path.as_std_path().fs_err_canonicalize()?,
    )?)
}

fn paths_match(virtpy: &StdPath, link_target: &StdPath) -> EResult<bool> {
    Ok(virtpy.fs_err_canonicalize()? == link_target.fs_err_canonicalize()?)
}

#[cfg(test)]
mod test {
    use camino::Utf8PathBuf;

    use super::*;
    use crate::{python::detection::detect, test::test_proj_dirs};

    #[test]
    fn get_install_paths() -> EResult<()> {
        let proj_dirs = test_proj_dirs();
        let tmp_dir = tempdir::TempDir::new("virtpy_test")?;
        let virtpy_path: Utf8PathBuf = tmp_dir.path().join("install_paths_test").try_into()?;
        let virtpy = Virtpy::create(&proj_dirs, &detect("3")?, &virtpy_path, None, None)?;
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
}
