use eyre::WrapErr;
use std::{
    collections::HashMap,
    fmt::Display,
    io::{Read, Seek},
    path::Path,
};

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
}
