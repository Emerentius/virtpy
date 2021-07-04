use eyre::WrapErr;

use crate::{
    delete_virtpy_backing, hash_of_file_sha256_base64, python_wheel::RecordEntry,
    virtpy_link_location, virtpy_link_target, virtpy_status, Distribution, EResult, Options,
    PathBuf, ProjectDirs, StoredDistributions, VirtpyBacking, VirtpyPaths, VirtpyStatus,
    INVALID_UTF8_PATH,
};
use std::{collections::HashMap, convert::TryInto};

// TODO: make into newtype
//       Maybe replace with FileHash?
type PackageFileHash = String;

fn collect_garbage(proj_dirs: &ProjectDirs, remove: bool, options: Options) -> EResult<()> {
    let mut danglers = vec![];
    for virtpy in proj_dirs.virtpys().read_dir().unwrap() {
        let virtpy = virtpy.unwrap();
        assert!(virtpy.file_type().unwrap().is_dir());
        let path = virtpy.path();

        match virtpy_status(&path) {
            Ok(VirtpyStatus::Ok { .. }) => (),
            Ok(VirtpyStatus::Orphaned { link }) => danglers.push((path, link)),
            Err(err) => println!("failed to check {}: {}", path, err),
        };
    }

    if danglers.len() != 0 {
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
        let unused_dists = unused_distributions(&proj_dirs).collect::<Vec<_>>();
        if !unused_dists.is_empty() {
            println!("found {} modules without users.", unused_dists.len());

            if remove {
                let mut stored_distribs = StoredDistributions::load(&proj_dirs)?;

                let dist_info_dir = proj_dirs.dist_infos();
                for dist in unused_dists {
                    let path = dist.path(&proj_dirs);
                    assert!(path.starts_with(&dist_info_dir));

                    println!("Removing {} {} ({})", dist.name, dist.version, dist.sha);

                    let res = fs_err::remove_dir_all(path);

                    // Remove distribution from list of installed distributions, for all
                    // python versions.
                    // Save after each attempted removal in case a bug causes the removal to fail prematurely
                    let hash = dist.sha;
                    for python_specific_stored_distribs in stored_distribs.0.values_mut() {
                        python_specific_stored_distribs.remove(&hash);
                    }
                    stored_distribs
                        .save(&proj_dirs)
                        .wrap_err("failed to save stored distributions")?;

                    res.unwrap();
                }
            }
        }
    }

    {
        let unused_package_files = unused_package_files(&proj_dirs).collect::<Vec<_>>();
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

fn print_verify_store(proj_dirs: &ProjectDirs) {
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

fn print_stats(proj_dirs: &ProjectDirs, options: Options) {
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
        .map(|(distr, dependents)| distribution_files[distr].1 * dependents.len() as u64)
        .sum::<u64>();

    println!("total space used: {}", total_size);
    println!(
        "total space used with duplication: {}",
        total_size_with_duplicates
    );

    println!(
        "total space saved: {}",
        total_size_with_duplicates - total_size
    );

    if options.verbose >= 1 {
        println!();
        for (distr, dependents) in distribution_dependents {
            println!(
                "{:30} {} dependents    ({})",
                format!("{} {}", distr.name, distr.version,),
                dependents.len(),
                distr.sha
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
}

fn file_dependents<'a>(
    proj_dirs: &ProjectDirs,
    distribution_files: &HashMap<Distribution, (Vec<RecordEntry>, u64)>,
) -> HashMap<PackageFileHash, Vec<Distribution>> {
    let mut dependents = HashMap::new();

    for file in proj_dirs
        .package_files()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .map(|dir_entry| {
            dir_entry
                .path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned()
        })
    {
        let hash = file;
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
fn distributions_dependents(proj_dirs: &ProjectDirs) -> HashMap<Distribution, Vec<PathBuf>> {
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
        .map(|entry| entry.path())
    {
        let virtpy_dirs = VirtpyBacking::from_path(virtpy_path.clone());
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
) -> HashMap<Distribution, (Vec<RecordEntry>, u64)> {
    proj_dirs
        .installed_distributions()
        .map(|distribution| {
            let records = distribution
                .records(proj_dirs)
                .unwrap()
                .map(Result::unwrap)
                .filter(|record| {
                    // FIXME: files with ../../
                    proj_dirs.package_files().join(&record.hash).exists()
                })
                .collect::<Vec<_>>();

            let total_size = records.iter().map(|record| record.filesize).sum::<u64>();
            assert_ne!(total_size, 0);
            (distribution, (records, total_size))
        })
        .collect()
}

fn distributions_used(virtpy_dirs: VirtpyBacking) -> impl Iterator<Item = Distribution> {
    virtpy_dirs
        .dist_infos()
        .map(|dist_info_path| dist_info_path.read_link().unwrap())
        .map(|store_dist_info| {
            Distribution::from_store_name(store_dist_info.file_name().unwrap().to_str().unwrap())
        })
}

fn unused_distributions(proj_dirs: &ProjectDirs) -> impl Iterator<Item = Distribution> + '_ {
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
