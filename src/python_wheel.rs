use eyre::WrapErr;
use std::{
    collections::HashMap,
    fmt::Display,
    io::{Read, Seek},
    path::{Path, PathBuf},
};

use crate::DependencyHash;

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
        let captures = lazy_regex::regex!(r"^(\d+)\.(\d+)$")
            .captures(version)
            .ok_or_else(|| {
                eyre::eyre!(
                    "version does not match format $MAJOR_NUM.$MINOR_NUM: {}",
                    version
                )
            })?;

        Ok(Self {
            major: captures[1]
                .parse()
                .wrap_err("could not parse major version number")?,
            minor: captures[2]
                .parse()
                .wrap_err("could not parse minor version number")?,
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

impl WheelVersionSupport {
    fn is_supported(&self) -> bool {
        match self {
            Self::Supported | Self::SupportedButNewer(_) => true,
            Self::Unsupported => false,
        }
    }
}

// Metadata about the wheel archive itself, not the contained package
struct WheelMetadata {
    version: WheelFormatVersion,
    generator: String, // (String, Option<String>), // generator name and optional version
    root_is_purelib: bool,
    tags: Vec<String>,
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
    // TODO: change to `own_path` and store the path to self.
    pub wheel_name: Option<String>,
    // All files in the record except for the record itself.
    pub files: Vec<RecordEntry>,
}

#[derive(
    Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Clone,
)]
pub struct RecordEntry {
    pub path: PathBuf,
    pub hash: DependencyHash,
    pub filesize: u64,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq, Hash, Clone)]
struct MaybeRecordEntry {
    path: String,
    hash: String,
    filesize: Option<u64>,
}

impl WheelRecord {
    fn from_str(record: &str) -> eyre::Result<Self> {
        let reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(record.as_bytes());

        Self::_from_csv_reader(reader)
    }

    pub fn from_file(record: impl AsRef<Path>) -> eyre::Result<Self> {
        let reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_path(record.as_ref())?;

        Self::_from_csv_reader(reader)
    }

    // Create a record of all files in a directory.
    // A wheel can contain a data directory of the form `<package>_<version>.data/<sysconfigpath>/whatever`.
    // This directory is not recorded in the dist-info for whatever dumb reason.
    // Consequently, one can't check integrity of the files there but we still need a record so we can add
    // the files to the internal repository and to get them back out.
    fn create_for_dir(dir: &Path) -> eyre::Result<Self> {
        eyre::ensure!(dir.is_dir(), "target is not a directory: {}", dir.display());
        let parent = dir
            .parent()
            .ok_or_else(|| eyre::eyre!("can't get parent of dir {:?}", dir))?;

        let mut files = vec![];
        for entry in walkdir::WalkDir::new(dir) {
            let entry = entry?;
            let metadata = entry.metadata()?;
            let filetype = metadata.file_type();
            if filetype.is_dir() {
                continue;
            }
            eyre::ensure!(
                !filetype.is_symlink(),
                "can't create record for dir containing symlinks. symlink found at: {:?}",
                entry.path()
            );

            files.push(RecordEntry {
                path: entry.path().strip_prefix(parent)?.to_owned(), // strip_prefix shouldn't ever fail here
                hash: DependencyHash(format!(
                    "sha256={}",
                    crate::hash_of_file_sha256(entry.path())
                )),
                filesize: metadata.len(),
            })
        }

        Ok(Self {
            wheel_name: None,
            files,
        })
    }

    fn save_to_file(&self, dest: &Path) -> eyre::Result<()> {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_path(dest)?;

        self._to_writer(&mut writer)
    }

    fn to_string(&self) -> String {
        let mut writer = csv::WriterBuilder::new()
            .has_headers(false)
            .from_writer(vec![]);
        self._to_writer(&mut writer).unwrap();

        String::from_utf8(writer.into_inner().unwrap()).unwrap()
    }

    fn _from_csv_reader<R: std::io::Read>(reader: csv::Reader<R>) -> eyre::Result<Self> {
        let files = reader
            .into_records()
            .map(|record| record.and_then(|rec| rec.deserialize(None)))
            .collect::<Result<Vec<MaybeRecordEntry>, _>>()?;

        // TODO: add verification
        let wheel_name = files
            .iter()
            .find_map(|f| f.path.strip_suffix(".dist-info/RECORD"))
            .map(<_>::to_owned);
        let files = files
            .into_iter()
            .filter(|entry| entry.filesize.is_some())
            .map(|entry| RecordEntry {
                path: entry.path.into(),
                hash: DependencyHash(entry.hash),
                filesize: entry.filesize.unwrap(),
            })
            .collect::<Vec<_>>();

        Ok(Self { files, wheel_name })
    }

    fn _to_writer<W: std::io::Write>(&self, writer: &mut csv::Writer<W>) -> eyre::Result<()> {
        for entry in &self.files {
            writer.serialize(entry)?;
        }
        if let Some(wheel_name) = &self.wheel_name {
            writer.serialize(MaybeRecordEntry {
                path: format!("{}.dist-info/RECORD", wheel_name),
                hash: String::new(),
                filesize: None,
            })?;
        }
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

    #[test]
    fn create_record_for_data_dir() -> eyre::Result<()> {
        let mut record = WheelRecord::create_for_dir("test_files/foo-1.0.data".as_ref())?;
        record.files.sort();

        assert_eq!(
            record,
            WheelRecord {
                wheel_name: None,
                files: vec![
                    RecordEntry {
                        path: "foo-1.0.data/data/some_data.json".into(),
                        hash: DependencyHash(
                            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_owned()
                        ),
                        filesize: 0
                    },
                    RecordEntry {
                        path: "foo-1.0.data/include/header.h".into(),
                        hash: DependencyHash(
                            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_owned()
                        ),
                        filesize: 0
                    },
                    RecordEntry {
                        path: "foo-1.0.data/platlib/conflicting".into(),
                        hash: DependencyHash(
                            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_owned()
                        ),
                        filesize: 0
                    },
                    RecordEntry {
                        path: "foo-1.0.data/purelib/conflicting".into(),
                        hash: DependencyHash(
                            "sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_owned()
                        ),
                        filesize: 0
                    },
                    RecordEntry {
                        path: "foo-1.0.data/scripts/rewrite_me.py".into(),
                        hash: DependencyHash(
                            "sha256=rkVeTeb1PZLAeS6yS3oqEEGwMnZrcz3ngLHWVw3aDVs".to_owned()
                        ),
                        filesize: 25
                    }
                ],
            }
        );
        Ok(())
    }
}
