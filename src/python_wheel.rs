use eyre::WrapErr;
use std::{
    collections::HashMap,
    fmt::Display,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use crate::FileHash;

// This implements a wheel installer following the specification here:
// https://packaging.python.org/specifications/binary-distribution-format/
// The format was originally defined in PEP 427, but the above may contain ammendments.
// https://www.python.org/dev/peps/pep-0427/
// Note that while PEP 491 exists, which defines a newer version of the wheel format,
// this is NOT an accepted PEP, it is deferred and may have diverged from the current specification
// linked above.
// https://www.python.org/dev/peps/pep-0491/#pep-deferral

pub fn unpack_wheel(wheel: &Path, dest: &Path) -> eyre::Result<()> {
    let mut archive = zip::ZipArchive::new(fs_err::File::open(wheel)?)?;

    let wheel_name = wheel
        .file_name()
        .ok_or_else(|| eyre::eyre!("wheel path does not point to file"))?
        .to_str()
        .ok_or_else(|| eyre::eyre!("wheel name is not valid utf8: {}", wheel.display()))?;
    let metadata = parse_wheel_metadata(wheel_name, &mut archive)?;
    check_version_support(wheel_name, metadata)?;

    archive.extract(dest)?;
    Ok(())
}

// fn verify_wheel_contents(wheel_name: &str, dest: &Path) {
//     let record = crate::records(record);
// }

fn check_version_support(wheel_name: &str, metadata: WheelMetadata) -> eyre::Result<()> {
    match metadata.version.support_status() {
        WheelVersionSupport::SupportedButNewer(supported_version) => println!("Warning: wheel {} uses a compatible, but newer version than supported: wheel format version: {}, newest supported: {}", wheel_name, metadata.version, supported_version),
        WheelVersionSupport::Unsupported => {
            eyre::bail!("wheel uses unsupported version {}", metadata.version)
        }
        WheelVersionSupport::Supported => (),
    };
    Ok(())
}

fn parse_wheel_metadata<R: Read + Seek>(
    wheel_name: &str,
    wheel_archive: &mut zip::ZipArchive<R>,
) -> eyre::Result<WheelMetadata> {
    let dist_info_name = wheel_dist_info_path(wheel_name)?;
    let wheel_version_file = format!("{}/WHEEL", dist_info_name);
    let mut wheel_version_file = wheel_archive
        .by_name(&wheel_version_file)
        .wrap_err(format!("could not find {}", wheel_version_file))?;
    let mut wheel_metadata = String::new();
    wheel_version_file.read_to_string(&mut wheel_metadata)?;

    WheelMetadata::from_str(&wheel_metadata)
}

fn wheel_dist_info_path(wheel_name: &str) -> eyre::Result<String> {
    let (idx, _) = wheel_name.char_indices().filter(|&(_, ch)| ch == '-')
    .nth(1).ok_or_else(|| eyre::eyre!("deformed wheel name, could not determine distribition and version from wheel name {}", wheel_name))?;

    Ok(format!("{}.dist-info", &wheel_name[..idx]))
}

//fn install_wheel()

// They never define the version format outright, but the wheel format docs mention
// major and minor version and how to handle those so I assume the version is just those
// two numbers.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Hash)]
struct WheelFormatVersion {
    major: u32,
    minor: u32,
}

impl WheelFormatVersion {
    // All newest versions that are supported per major number.
    const SUPPORTED: &'static [WheelFormatVersion] = &[WheelFormatVersion { major: 1, minor: 0 }];

    fn from_str(version: &str) -> eyre::Result<Self> {
        let (_, major, minor) = lazy_regex::regex_captures!(r"^(\d+)\.(\d+)$", version)
            .ok_or_else(|| {
                eyre::eyre!(
                    "version does not match format $MAJOR_NUM.$MINOR_NUM: {}",
                    version
                )
            })?;

        let parse_version = |num: &str, info: &str| {
            num.parse().wrap_err_with(|| {
                eyre::eyre!("could not parse {} version number: \"{:?}\"", info, num)
            })
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

// Metadata about the wheel archive itself, not the contained package
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
    fn from_str(metadata: &str) -> eyre::Result<Self> {
        // First, read all key-value pairs so we can collect all tags into a vec and also detect duplicates.
        // Unknown keys are ignored. They may be from a newer wheel format version.
        let mut key_values: HashMap<_, Vec<_>> = HashMap::new();

        for line in metadata
            .lines()
            .map(str::trim_end)
            .filter(|l| !l.is_empty())
        {
            let (key, value) = line
                .split_once(": ")
                .ok_or_else(|| eyre::eyre!("found key without value: {:?}", line))?;
            key_values.entry(key).or_default().push(value);
        }

        let get_unique_optional = |key| match key_values.get(key) {
            Some(x) if x.len() == 1 => Ok(Some(x[0].to_owned())),
            Some(_) => Err(eyre::eyre!("multiple key-value pairs for key {}", key)),
            None => return Ok(None),
        };

        let get_unique = |key| {
            get_unique_optional(key).and_then(|opt_val| {
                opt_val.ok_or_else(|| eyre::eyre!("missing required key {}", key))
            })
        };

        let parse_bool = |value| match value {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(eyre::eyre!("invalid value for boolean: {:?}", value)),
        };

        Ok(WheelMetadata {
            version: WheelFormatVersion::from_str(&get_unique("Wheel-Version")?)?,
            generator: get_unique("Generator")?,
            root_is_purelib: parse_bool(&get_unique("Root-Is-Purelib")?)?,
            tags: key_values
                .get("Tag")
                .map(|v| v.iter().map(<_>::to_string).collect())
                .unwrap_or_default(),
            build: get_unique_optional("Build")?,
        })
    }
}

#[derive(PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct WheelRecord {
    // stored separately just so we can easily recreate the line for the RECORD itself
    // without making paths and filesizes optional for all other files.
    // If `None`, don't write a RECORD line.
    pub record_path: PathBuf,
    // All files in the record except for the record itself.
    pub files: Vec<RecordEntry>,
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
pub struct RecordEntry {
    pub path: PathBuf,
    pub hash: FileHash,
    pub filesize: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Clone)]
struct MaybeRecordEntry {
    path: PathBuf,
    hash: String,
    filesize: Option<u64>,
}

impl WheelRecord {
    // fn from_str(record: &str) -> eyre::Result<Self> {
    //     let reader = csv::ReaderBuilder::new()
    //         .has_headers(false)
    //         .from_reader(record.as_bytes());

    //     Self::_from_csv_reader(reader)
    // }

    pub fn from_file(record: impl AsRef<Path>) -> eyre::Result<Self> {
        let reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(record.as_ref())?;

        Self::_from_csv_reader(reader)
            .wrap_err_with(|| eyre::eyre!("failed to read record from {:?}", record.as_ref()))
    }

    pub fn save_to_file(&self, dest: impl AsRef<Path>) -> eyre::Result<()> {
        let dest = dest.as_ref();
        self._save_to_file(dest)
            .wrap_err_with(|| eyre::eyre!("failed to save record to {:?}", dest))
    }

    fn _save_to_file(&self, dest: &Path) -> eyre::Result<()> {
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

    fn _from_csv_reader<R: std::io::Read>(reader: csv::Reader<R>) -> eyre::Result<Self> {
        let files = reader
            .into_records()
            .map(|record| record.and_then(|rec| rec.deserialize(None)))
            .collect::<Result<Vec<MaybeRecordEntry>, _>>()?;

        // TODO: add verification
        let record_path = files
            .iter()
            .find(|f| {
                f.path.as_path().to_str().map_or(false, |path| {
                    lazy_regex::regex_is_match!(r"[^-/]+-[^-/]+\.dist-info/RECORD", path)
                })
            })
            .ok_or_else(|| eyre::eyre!("RECORD does not contain path to itself"))?
            .path
            .clone();
        let files = files
            .into_iter()
            .filter(|entry| entry.filesize.is_some())
            .map(|entry| RecordEntry {
                path: entry.path.into(),
                hash: FileHash(entry.hash),
                filesize: entry.filesize.unwrap(),
            })
            .collect::<Vec<_>>();

        Ok(Self { files, record_path })
    }

    fn _to_writer<W: std::io::Write>(&self, writer: &mut csv::Writer<W>) -> eyre::Result<()> {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn can_unpack_wheel() -> eyre::Result<()> {
        let tmp_dir = tempdir::TempDir::new("virtpy_wheel_unpack_test")?;
        unpack_wheel(
            "test_files/wheels/result-0.6.0-py3-none-any.whl".as_ref(),
            tmp_dir.path(),
        )?;
        Ok(())
    }

    #[test]
    fn can_parse_wheel_metadata_from_zip() -> eyre::Result<()> {
        let wheel_name = "result-0.6.0-py3-none-any.whl";
        let wheel = Path::new("test_files/wheels/").join(wheel_name);
        let mut archive = zip::ZipArchive::new(fs_err::File::open(wheel)?)?;

        let metadata = parse_wheel_metadata(wheel_name, &mut archive)?;
        assert_eq!(metadata.version, WheelFormatVersion { major: 1, minor: 0 });
        Ok(())
    }

    #[test]
    fn can_parse_wheel_metadata() -> eyre::Result<()> {
        // TODO: add check for correctness of read metadata
        // Some of the files contain CRLF line endings, some LF.
        // Both must work.
        for f in Path::new("test_files/wheel_metadata").read_dir()? {
            let f = f?;
            let data = fs_err::read_to_string(f.path())?;
            WheelMetadata::from_str(&data)
                .wrap_err_with(|| eyre::eyre!("failed to parse data for {:?}", f.path()))?;
        }
        Ok(())
    }

    #[test]
    fn read_record() -> eyre::Result<()> {
        for f in Path::new("test_files/wheel_records").read_dir()? {
            let f = f?;
            WheelRecord::from_file(f.path())?;
        }
        WheelRecord::from_file("test_files/RECORD")?;
        Ok(())
    }
}
