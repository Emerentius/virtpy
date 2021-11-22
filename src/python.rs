use crate::{check_output, check_status, is_not_found, relative_path, EResult, Path};
use crate::{PathBuf, ProjectDirs};
use eyre::eyre;
use eyre::Context;
use std::fmt::Write;

use self::requirements::Requirement;
use self::wheel::RecordEntry;

pub(crate) mod detection;
pub(crate) mod requirements;
pub(crate) mod wheel;

// probably missing prereleases and such
// TODO: check official scheme
#[derive(Copy, Clone)]
pub(crate) struct PythonVersion {
    // TODO: make these u32
    pub(crate) major: i32,
    pub(crate) minor: i32,
    #[allow(unused)]
    pub(crate) patch: i32,
}

impl PythonVersion {
    pub(crate) fn as_string_without_patch(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

pub(crate) fn python_version(python_path: &Path) -> EResult<PythonVersion> {
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
pub(crate) struct DistributionHash(pub(crate) String);

// The base64 encoded hash of a file in a wheel.
// has the form "sha256=${base64_encoded_string}"
#[derive(
    Clone, Hash, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[must_use]
pub(crate) struct FileHash(pub(crate) String);

impl std::fmt::Display for FileHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<Path> for FileHash {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl DistributionHash {
    pub(crate) fn from_file(path: &Path) -> Self {
        Self(format!("sha256={}", hash_of_file_sha256_base16(path)))
    }
}

impl FileHash {
    // TODO: use when checking file hashes in RECORD to be correct
    #[allow(unused)]
    pub(crate) fn from_file(path: &Path) -> Self {
        Self::from_hash(hash_of_file_sha256_base64(path))
    }

    // files in the repository are named after their hash, so we can just use the filename
    pub(crate) fn from_filename(path: &Path) -> Self {
        Self(path.file_name().unwrap().to_owned())
    }

    pub(crate) fn from_reader(reader: impl std::io::Read) -> Self {
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

// returns all files recorded in RECORDS, except for .dist-info files
pub(crate) fn records(
    record: &Path,
) -> csv::Result<impl Iterator<Item = csv::Result<RecordEntry>>> {
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

pub(crate) fn serialize_requirements_txt(reqs: &[Requirement]) -> String {
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

#[derive(PartialEq, Eq, Debug)]
pub(crate) struct EntryPoint {
    pub(crate) name: String,
    pub(crate) module: String,
    pub(crate) qualname: Option<String>,
    // optional and now deprecated
    //extras: Option<Vec<String>>
}

impl EntryPoint {
    // construct from entry_points ini entry
    pub(crate) fn new(key: &str, value: &str) -> Self {
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

    pub(crate) fn generate_executable(
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

pub(crate) fn generate_executable(
    dest: &Path,
    python_path: &Path,
    code: &str,
    site_packages: &Path,
) -> std::io::Result<RecordEntry> {
    let shebang = format!("#!{}", python_path);
    #[cfg(unix)]
    {
        _generate_executable(
            dest,
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
        path: relative_path(site_packages, dest),
        hash: FileHash::from_reader(bytes),
        filesize: bytes.len() as u64,
    })
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct Distribution {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) sha: DistributionHash,
}

impl Distribution {
    pub(crate) fn from_store_name(store_name: &str) -> Self {
        let (_, name, version, hash) =
            lazy_regex::regex_captures!(r"([^,]+),([^,]+),([^,]+)", store_name).unwrap();

        Self {
            name: name.to_owned(),
            version: version.to_owned(),
            sha: DistributionHash(hash.to_owned()),
        }
    }

    pub(crate) fn as_csv(&self) -> String {
        format!("{},{},{}", self.name, self.version, self.sha)
    }

    pub(crate) fn name_and_version(&self) -> String {
        // used for the dist-info directory and some error reports
        format!("{}-{}", self.name, self.version)
    }

    pub(crate) fn dist_info_name(&self) -> String {
        format!("{}-{}.dist-info", self.name, self.version)
    }

    pub(crate) fn data_dir_name(&self) -> String {
        format!("{}-{}.data", self.name, self.version)
    }
}

pub(crate) fn print_error_missing_file_in_record(distribution: &Distribution, missing_file: &Path) {
    println!(
        "couldn't find recorded file from {}: {}",
        distribution.name_and_version(),
        missing_file
    )
}

pub(crate) fn entrypoints(path: &Path) -> Option<Vec<EntryPoint>> {
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
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    std::io::copy(&mut reader, &mut hasher).unwrap();
    hasher.finalize()
}

// Converts a non-wheel distribution of some type into a wheel.
// This can be a egg, a tarball (typically gzipped, but other compression algorithms are possible as well as uncompressed),
// or a zip file.
//
// Returns the path to the wheel and the TempDir that contains the wheel file.
// The TempDir needs to be preserved until the wheel has been used or copied elsewhere as it'll be
// deleted with the TempDir.
pub(crate) fn convert_to_wheel(
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
                .expect(crate::INVALID_UTF8_PATH);
            Ok((wheel_path, output_dir))
        }
        _ => Err(eyre!("wheel generation created more than one file")),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn read_entrypoints() {
        let entrypoints =
            entrypoints("test_files/entrypoints.dist-info/entry_points.txt".as_ref()).unwrap();
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
}
