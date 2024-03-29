use crate::prelude::*;
use eyre::{bail, eyre, WrapErr};
use fs_err::PathExt;
use std::{
    collections::HashMap,
    fmt::Display,
    io::{Read, Seek},
    path::Path as StdPath,
};

use super::FileHash;
use crate::{Path, PathBuf};

// This implements a wheel installer following the specification here:
// https://packaging.python.org/specifications/binary-distribution-format/
// The format was originally defined in PEP 427, but the above may contain ammendments.
// https://www.python.org/dev/peps/pep-0427/
// Note that while PEP 491 exists, which defines a newer version of the wheel format,
// this is NOT an accepted PEP, it is deferred and may have diverged from the current specification
// linked above.
// https://www.python.org/dev/peps/pep-0491/#pep-deferral

pub(crate) fn unpack_wheel(wheel: &Path, dest: &StdPath) -> Result<()> {
    let mut archive = zip::ZipArchive::new(fs_err::File::open(wheel)?)?;

    let wheel_name = wheel
        .file_name()
        .ok_or_else(|| eyre!("wheel path does not point to file"))?;
    let metadata = parse_wheel_metadata(wheel_name, &mut archive)?;
    check_version_support(wheel_name, metadata)?;

    archive
        .extract(dest)
        .wrap_err_with(|| eyre!("failed to extract wheel to {dest:?}"))?;
    Ok(())
}

fn check_version_support(wheel_name: &str, metadata: WheelMetadata) -> Result<()> {
    match metadata.version.support_status() {
        WheelVersionSupport::SupportedButNewer(supported_version) => println!("Warning: wheel {wheel_name} uses a compatible, but newer version than supported: wheel format version: {}, newest supported: {supported_version}", metadata.version),
        WheelVersionSupport::Unsupported => bail!("wheel uses unsupported version {}", metadata.version),
        WheelVersionSupport::Supported => (),
    };
    Ok(())
}

fn parse_wheel_metadata<R: Read + Seek>(
    wheel_name: &str,
    wheel_archive: &mut zip::ZipArchive<R>,
) -> Result<WheelMetadata> {
    let dist_info_name = wheel_dist_info_path(wheel_name)?;
    let wheel_version_file = format!("{dist_info_name}/WHEEL");
    let mut wheel_version_file = wheel_archive
        .by_name(&wheel_version_file)
        .wrap_err(format!("could not find {wheel_version_file}"))?;
    let mut wheel_metadata = String::new();
    wheel_version_file.read_to_string(&mut wheel_metadata)?;

    WheelMetadata::from_str(&wheel_metadata)
}

fn wheel_dist_info_path(wheel_name: &str) -> Result<String> {
    let (idx, _) = wheel_name.char_indices().filter(|&(_, ch)| ch == '-')
    .nth(1).ok_or_else(|| eyre!("deformed wheel name, could not determine distribition and version from wheel name {wheel_name}"))?;

    Ok(format!("{}.dist-info", &wheel_name[..idx]))
}

//fn install_wheel()

/// The version of the wheel packaging format (not of the packaged code)
/// The specification (https://packaging.python.org/specifications/binary-distribution-format/)
/// never actually defines the version format, but the docs reference
/// major and minor version and how to handle those so I assume the version is just those
/// two numbers.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
struct WheelFormatVersion {
    major: u32,
    minor: u32,
}

impl WheelFormatVersion {
    // All newest versions that are supported per major number.
    const SUPPORTED: &'static [WheelFormatVersion] = &[WheelFormatVersion { major: 1, minor: 0 }];

    fn from_str(version: &str) -> Result<Self> {
        let (_, major, minor) = lazy_regex::regex_captures!(r"^(\d+)\.(\d+)$", version)
            .ok_or_else(|| {
                eyre!("version does not match format $MAJOR_NUM.$MINOR_NUM: {version}")
            })?;

        let parse_version = |num: &str, info: &str| {
            num.parse()
                .wrap_err_with(|| eyre!("could not parse {info} version number: \"{num:?}\""))
        };
        Ok(Self {
            major: parse_version(major, "major")?,
            minor: parse_version(minor, "minor")?,
        })
    }

    fn support_status(&self) -> WheelVersionSupport {
        match Self::SUPPORTED
            .iter()
            .find(|supported_version| self.major == supported_version.major)
        {
            Some(supported_version) if supported_version.minor >= self.minor => {
                WheelVersionSupport::Supported
            }
            Some(&supported_version) => WheelVersionSupport::SupportedButNewer(supported_version),
            None => WheelVersionSupport::Unsupported,
        }
    }
}

// You're supposed to emit a warning, if a wheel uses a compatible, but newer wheel format version.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WheelVersionSupport {
    Supported,
    // contains the latest supported version with same major number
    SupportedButNewer(WheelFormatVersion),
    Unsupported,
}

/// Metadata about the wheel archive itself, not the contained package.
/// Stored in the file `WHEEL` in a wheel's dist-info directory.
struct WheelMetadata {
    version: WheelFormatVersion,
    #[allow(unused)]
    generator: String, // (String, Option<String>), // generator name and optional version
    // TODO: respect the purelib / platlib distinction
    #[allow(unused)]
    root_is_purelib: bool,
    // TODO: check via tags that this wheel is for our platform
    #[allow(unused)]
    tags: Vec<String>,
    #[allow(unused)]
    build: Option<String>,
}

impl Display for WheelFormatVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl WheelMetadata {
    fn from_str(metadata: &str) -> Result<Self> {
        // First, read all key-value pairs so we can collect all tags into a vec and also detect duplicates.
        // Unknown keys are ignored. They may be from a newer wheel format version.
        let kv = KeyValues::from_str(metadata);

        Ok(WheelMetadata {
            version: WheelFormatVersion::from_str(&kv.get_unique("Wheel-Version")?)?,
            generator: kv.get_unique("Generator")?,
            root_is_purelib: KeyValues::parse_bool(&kv.get_unique("Root-Is-Purelib")?)?,
            tags: kv.0.get("Tag").cloned().unwrap_or_default(),
            build: kv.get_unique_optional("Build")?,
        })
    }
}

/// Metadata about the distribution package as defined by
/// https://packaging.python.org/en/latest/specifications/core-metadata/#core-metadata
/// Stored in the file `METADATA` in a wheel's dist-info directory.
pub struct DistributionMetadata {
    // name, version and metadatavversion are required, everything else is
    // optional
    pub metadata_version: String,
    pub name: String,
    pub version: String,
    // and a whole lot of other things
}

impl DistributionMetadata {
    pub fn from_str(metadata: &str) -> Result<Self> {
        let kv = KeyValues::from_str(metadata);

        // Automated tools consuming metadata [...] MUST fail if metadata_version has a greater
        // major version than the highest version they support
        let metadata_version = kv.get_unique("Metadata-Version")?;
        let major_version = metadata_version
            .get(..2)
            .ok_or_else(|| eyre!("distribution metadata version is missing major version"))?;
        if !["1.", "2."].contains(&major_version) {
            eyre::bail!("unsupported version of distribution metadata");
        }
        Ok(DistributionMetadata {
            name: kv.get_unique("Name")?,
            version: kv.get_unique("Version")?,
            metadata_version: kv.get_unique("Metadata-Version")?,
        })
    }
}

/// Helper struct for reading METADATA and WHEEL files
struct KeyValues(HashMap<String, Vec<String>>);

impl KeyValues {
    fn from_str(string: &str) -> Self {
        // First, read all key-value pairs so we can collect all tags into a vec and also detect duplicates.
        // Unknown keys are ignored. They may be from a newer wheel format version.
        let mut key_values: HashMap<_, Vec<_>> = HashMap::new();

        for line in string
            .lines()
            // Once a blank line appears, everything after it is part of the description.
            // We mustn't read it, lest we mistake part of it for a key-value pair.
            .take_while(|l| !l.is_empty())
            .map(str::trim_end)
        {
            let (key, value) = match line.split_once(": ") {
                Some(x) => x,
                // There can be a block below the key-values.
                // In the METADATA file that contains something like a README.
                None => continue,
            };
            key_values
                .entry(key.to_owned())
                .or_default()
                .push(value.to_owned());
        }
        Self(key_values)
    }

    fn get_unique_optional(&self, key: &str) -> Result<Option<String>> {
        match self.0.get(key).map(|v| v.as_slice()) {
            Some([value]) => Ok(Some(value.clone())),
            Some(_) => Err(eyre!("multiple key-value pairs for key {key}")),
            None => Ok(None),
        }
    }

    fn get_unique(&self, key: &str) -> Result<String> {
        self.get_unique_optional(key)
            .and_then(|opt_val| opt_val.ok_or_else(|| eyre!("missing required key {}", key)))
    }

    fn parse_bool(value: &str) -> Result<bool> {
        match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(eyre!("invalid value for boolean: {value:?}")),
        }
    }
}

// Following https://packaging.python.org/specifications/binary-distribution-format/#escaping-and-unicode
// This is important because the wheel name components may contain "-" characters,
// but those are separators in a wheel name.
// We need this because the dist-info and data directory contain the normalized distrib name.
// We may have to add version normalization, if we ever get unnormalized ones.
//
// NOTE: The specification claims:
// In distribution names, any run of -_. characters (HYPHEN-MINUS, LOW LINE and FULL STOP) should be
// replaced with _ (LOW LINE). This is equivalent to PEP 503 normalisation followed by replacing - with _.
//
// This is NOT TRUE. PEP 503 normalization includes conversion to lowercase. We MUST NOT do that.
// Package names out in the wild contain uppercase names and are accepted by pip.
pub(crate) fn normalized_distribution_name_for_wheel(distrib_name: &str) -> String {
    let pattern = lazy_regex::regex!(r"[-_]+");
    pattern.replace_all(distrib_name, "_").into_owned()
}

// fn _escape(string: &str, replace_with: &str) -> String {
//     let pattern = lazy_regex::regex!(r"[-_.]+");
//     pattern.replace_all(string, replace_with).into_owned()
// }

/// The record of all files belonging to a distribution along with their path, size and hash.
/// It is stored in the file `RECORD` inside a distribution's dist-info directory.
/// Exists only for packages distributed as wheels.
/// The installed distributions retain the record and any files that are newly generated
/// or moved to their target destinations from the data directory have to be added
/// to the record by the installer (i.e. us).
#[derive(PartialEq, Eq, Debug, Hash, PartialOrd, Ord, Clone)]
pub(crate) struct WheelRecord {
    // stored separately just so we can easily recreate the line for the RECORD itself
    // without making paths and filesizes optional for all other files.
    pub(crate) record_path: PathBuf,
    // All files in the record except for the record itself.
    pub(crate) files: Vec<RecordEntry>,
}

// On the distinction between RecordEntry and MaybeRecordEntry:
// MaybeRecordEntry is used only as an intermediate step for (de-)serialization.
// Internally, we use `RecordEntry` which upholds more invariants.
//
// The RECORD file is self-referential which causes some issue for the entry of itself.
// The file can't (feasibly) contain its own hash, because you can't compute the hash of the file
// if the file doesn't already contain the hash and for almost all hashes you put there, the file
// won't hash to that hash. It's like a quine, but worse.
// The self-referential entry doesn't contain the size either even though that one would actually
// be possible to put in.
//
// So, now all of the records have a path, hash and filesize except for one entry which has only a path
// and is of limited use anyway.
// We could deal with having optional-but-not-really hashes and filesizes everywhere,
// or we store the self-entry separately separately and have all the other entries
// use decent types.
#[derive(
    Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
#[must_use]
pub(crate) struct RecordEntry {
    pub(crate) path: PathBuf,
    pub(crate) hash: FileHash,
    pub(crate) filesize: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Clone)]
pub(crate) struct MaybeRecordEntry {
    pub(crate) path: PathBuf,
    pub(crate) hash: String,
    pub(crate) filesize: Option<u64>,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum RecordEntryError {
    #[error("record entry has no filesize: {0}")]
    MissingFilesize(PathBuf),
    #[error("record entry has invalid hash: {0}, hash = {1}")]
    InvalidHash(PathBuf, String),
}

impl TryFrom<MaybeRecordEntry> for RecordEntry {
    type Error = RecordEntryError;

    fn try_from(maybe_entry: MaybeRecordEntry) -> Result<Self, Self::Error> {
        let filesize = match maybe_entry.filesize {
            Some(size) => size,
            None => return Err(RecordEntryError::MissingFilesize(maybe_entry.path)),
        };
        let hash = maybe_entry.hash;
        if hash.len() != 50 || !hash.starts_with("sha256=") {
            return Err(RecordEntryError::InvalidHash(maybe_entry.path, hash));
        }

        Ok(Self {
            path: maybe_entry.path,
            hash: FileHash(hash),
            filesize,
        })
    }
}

impl From<RecordEntry> for MaybeRecordEntry {
    fn from(entry: RecordEntry) -> Self {
        Self {
            path: entry.path,
            hash: entry.hash.0,
            filesize: Some(entry.filesize),
        }
    }
}

impl WheelRecord {
    // fn from_str(record: &str) -> Result<Self> {
    //     let reader = csv::ReaderBuilder::new()
    //         .has_headers(false)
    //         .from_reader(record.as_bytes());

    //     Self::_from_csv_reader(reader)
    // }

    pub(crate) fn from_file(record: impl AsRef<Path>) -> Result<Self> {
        Self::_from_file(record.as_ref(), false)
    }

    // pub(crate) fn from_file_ignoring_pyc(record: impl AsRef<Path>) -> Result<Self> {
    //     Self::_from_file(record.as_ref(), true)
    // }

    fn _from_file(record: &Path, ignore_pyc_files: bool) -> Result<Self> {
        csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(record)
            .map_err(Into::into)
            .and_then(|reader| Self::_from_csv_reader(reader, ignore_pyc_files))
            .wrap_err_with(|| eyre!("failed to read record from {record:?}"))
    }

    pub(crate) fn save_to_file(&self, dest: impl AsRef<Path>) -> Result<()> {
        let dest = dest.as_ref();
        self._save_to_file(dest)
            .wrap_err_with(|| eyre!("failed to save record to {dest:?}"))
    }

    fn _save_to_file(&self, dest: &Path) -> Result<()> {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(dest)?;

        self._to_writer(&mut writer)
    }

    // fn to_string(&self) -> String {
    //     let mut writer = csv::WriterBuilder::new()
    //         .has_headers(false)
    //         .from_writer(vec![]);
    //     self._to_writer(&mut writer).unwrap();

    //     String::from_utf8(writer.into_inner().unwrap()).unwrap()
    // }

    fn _from_csv_reader<R: std::io::Read>(
        reader: csv::Reader<R>,
        ignore_pyc_files: bool,
    ) -> Result<Self> {
        let files = reader
            .into_records()
            .map(|record| record.and_then(|rec| rec.deserialize(None)))
            .collect::<Result<Vec<MaybeRecordEntry>, _>>()?;

        let record_path = files
            .iter()
            .find(|f| {
                lazy_regex::regex_is_match!(r"[^-/]+-[^-/]+\.dist-info/RECORD", f.path.as_str())
            })
            .ok_or_else(|| eyre!("RECORD does not contain path to itself"))?
            .path
            .clone();
        let files = files
            .into_iter()
            .filter(|entry| !(ignore_pyc_files && entry.path.extension() == Some("pyc")))
            .filter(|entry| !entry.path.ends_with("RECORD"))
            .map(RecordEntry::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { files, record_path })
    }

    fn _to_writer<W: std::io::Write>(&self, writer: &mut csv::Writer<W>) -> Result<()> {
        for entry in &self.files {
            writer.serialize(entry)?;
        }
        writer.serialize(MaybeRecordEntry {
            path: self.record_path.clone(),
            hash: String::new(),
            filesize: None,
        })?;
        Ok(())
    }
}

/// See verify_wheel_contents_or_repair() for additional info.
#[derive(clap::ValueEnum, Clone, Copy)]
pub(crate) enum CheckStrategy {
    /// Assume the distribution contents are correct and update its metadata when incorrect.
    /// This is in violation of the spec, but required because invalid wheels exist
    /// in the wild and we can't let them corrupt our internal content addressed store.
    Repair,
    /// Return an error when the wheel's metadata doesn't match its contents, i.e.
    /// when not all files are mentioned in the RECORD or their content's hashes don't match
    /// the one one in the wheel's RECORD.
    /// Correct behavior as per the spec:
    /// https://packaging.python.org/en/latest/specifications/binary-distribution-format/#the-dist-info-directory
    RejectInvalid,
}

/// Token
pub(crate) struct WheelChecked;

/// Check that the RECORD matches the wheel contents for an unpacked wheel distribution and repair it, if desired.
///
///
/// As stated in the wheel format specification
/// https:///packaging.python.org/en/latest/specifications/binary-distribution-format/#the-dist-info-directory
///
/// >During extraction, wheel installers verify all the hashes in RECORD against the file contents.
/// Apart from RECORD and its signatures, installation will fail if any file in the archive is not both
/// mentioned and correctly hashed in RECORD.
///
/// Pip, THE python package manager, neglected to implement this so now there are lots of invalid wheels
/// in the wild and we have to deal with them. Why am I not surprised?
///
/// Given that our pip shim calls virtpy non-interactively, we can't inform the user and prompt
/// whether they want to accept corrupted wheels.
/// We can automatically fix the wheels by computing the correct hash. If we simply accepted
/// files into the central store under whatever hash is in the RECORD, it would be trivial to maliciously
/// create collisions and overwrite another distribution's files.
pub(crate) fn verify_wheel_contents_or_repair(
    // directory into which the distribution has been unpackaged
    path: &Path,
    distribution: &super::Distribution,
    record: &mut WheelRecord,
    check_strategy: CheckStrategy,
) -> Result<WheelChecked> {
    let mut n_hash_updated = 0;
    let mut n_filesize_updated = 0;
    for entry in &mut record.files {
        let filepath = path.join(&entry.path);
        let filesize = filepath.as_std_path().fs_err_metadata()?.len();
        let filehash = FileHash::from_file(&filepath)?;
        let filesize_matches = filesize == entry.filesize;
        let hash_matches = filehash == entry.hash;
        match check_strategy {
            CheckStrategy::Repair => {
                // NOTE: As we're currently only supporting SHA256 file hashes, if the wheel record
                //       uses a different hash than SHA256, this will replace it.
                if !hash_matches {
                    entry.hash = filehash;
                    n_hash_updated += 1;
                }
                if !filesize_matches {
                    entry.filesize = filesize;
                    n_filesize_updated += 1;
                }
            }
            CheckStrategy::RejectInvalid => {
                eyre::ensure!(
                    filesize_matches,
                    "filesize doesn't match record: expected {}, got {filesize} for {}",
                    entry.filesize,
                    entry.path
                );
                eyre::ensure!(
                    hash_matches,
                    "filehash doesn't match record: expected {}, got {filehash} for {}",
                    entry.hash,
                    entry.path
                );
            }
        }
    }
    if n_filesize_updated > 0 || n_hash_updated > 0 {
        eprintln!(
            "updated record for new package {}: {} filesize mismatches, {} hash mismatches",
            distribution.name_and_version(),
            n_filesize_updated,
            n_hash_updated
        );
        record.save_to_file(path.join(&record.record_path))?;
    }

    Ok(WheelChecked)
}

#[cfg(test)]
mod test {
    use eyre::eyre;

    use crate::python::{Distribution, DistributionHash};

    use super::*;

    #[test]
    fn can_unpack_wheel() -> Result<()> {
        let tmp_dir = tempdir::TempDir::new("virtpy_wheel_unpack_test")?;
        unpack_wheel(
            "test_files/wheels/result-0.6.0-py3-none-any.whl".as_ref(),
            tmp_dir.path(),
        )?;
        Ok(())
    }

    #[test]
    fn can_parse_wheel_metadata_from_zip() -> Result<()> {
        let wheel_name = "result-0.6.0-py3-none-any.whl";
        let wheel = Path::new("test_files/wheels/").join(wheel_name);
        let mut archive = zip::ZipArchive::new(fs_err::File::open(wheel)?)?;

        let metadata = parse_wheel_metadata(wheel_name, &mut archive)?;
        assert_eq!(metadata.version, WheelFormatVersion { major: 1, minor: 0 });
        Ok(())
    }

    #[test]
    fn can_parse_wheel_metadata() -> Result<()> {
        // TODO: add check for correctness of read metadata
        // Some of the files contain CRLF line endings, some LF.
        // Both must work.
        for f in Path::new("test_files/wheel_metadata").read_dir()? {
            let f = f?;
            let data = fs_err::read_to_string(f.path())?;
            WheelMetadata::from_str(&data)
                .wrap_err_with(|| eyre!("failed to parse data for {:?}", f.path()))?;
        }
        Ok(())
    }

    #[test]
    fn can_parse_distribution_metadata() -> Result<()> {
        for f in Path::new("test_files/distribution_metadata").read_dir()? {
            let f = f?;
            let data = fs_err::read_to_string(f.path())?;
            DistributionMetadata::from_str(&data)
                .wrap_err_with(|| eyre!("failed to parse data for {:?}", f.path()))?;
        }
        Ok(())
    }

    #[test]
    fn read_record() -> Result<()> {
        for f in Path::new("test_files/wheel_records").read_dir()? {
            let f = f?;
            WheelRecord::from_file(PathBuf::from_path_buf(f.path()).unwrap())?;
        }
        WheelRecord::from_file("test_files/RECORD")?;
        Ok(())
    }

    #[test]
    fn verify_and_repair_wheel() -> Result<()> {
        // TODO: split this into multiple tests. It does too much.
        let tmp_dir_valid = tempdir::TempDir::new("virtpy_valid_wheel_verification_test")?;
        let tmp_dir_invalid = tempdir::TempDir::new("virtpy_invalid_wheel_verification_test")?;

        let package_name = "wheel_test_package-0.1.0-py3-none-any.whl";
        let valid_wheel =
            Path::new("test_files/wheels/validity_check_valid_wheel").join(package_name);
        let invalid_wheel =
            Path::new("test_files/wheels/validity_check_invalid_wheel").join(package_name);

        // we're not checking the hash, but a Distribution requires one
        let hash = DistributionHash::from_file(&valid_wheel)?;
        let dist = Distribution::from_package_name(package_name, hash)?;

        unpack_wheel(valid_wheel.as_ref(), tmp_dir_valid.path())?;
        unpack_wheel(invalid_wheel.as_ref(), tmp_dir_invalid.path())?;

        let record_valid = WheelRecord::from_file(
            tmp_dir_valid
                .utf8_path()
                .join(dist.dist_info_name())
                .join("RECORD"),
        )?;
        let record_invalid = WheelRecord::from_file(
            tmp_dir_invalid
                .utf8_path()
                .join(dist.dist_info_name())
                .join("RECORD"),
        )?;

        assert_ne!(record_valid, record_invalid);

        // Check that validity is correctly determined and
        // that RejectInvalid doesn't modify the record.
        let mut record_valid_copy = record_valid.clone();
        verify_wheel_contents_or_repair(
            tmp_dir_valid.utf8_path(),
            &dist,
            &mut record_valid_copy,
            CheckStrategy::RejectInvalid,
        )?;
        assert_eq!(record_valid_copy, record_valid);

        let mut record_invalid_copy = record_invalid.clone();
        assert!(verify_wheel_contents_or_repair(
            tmp_dir_invalid.utf8_path(),
            &dist,
            &mut record_invalid_copy,
            CheckStrategy::RejectInvalid
        )
        .is_err());
        assert_eq!(record_invalid_copy, record_invalid);

        // Check that repair does nothing for valid and repairs the invalid record
        // to match the valid one
        verify_wheel_contents_or_repair(
            tmp_dir_valid.utf8_path(),
            &dist,
            &mut record_valid_copy,
            CheckStrategy::Repair,
        )?;
        assert_eq!(record_valid_copy, record_valid);

        verify_wheel_contents_or_repair(
            tmp_dir_invalid.utf8_path(),
            &dist,
            &mut record_invalid_copy,
            CheckStrategy::Repair,
        )?;
        assert_eq!(record_invalid_copy, record_valid);

        Ok(())
    }
}
