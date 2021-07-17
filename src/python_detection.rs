use std::convert::TryInto;

use eyre::{bail, eyre, WrapErr};

use crate::{EResult, INVALID_UTF8_PATH};
use crate::{Path, PathBuf};

pub fn detect(python: &str) -> EResult<PathBuf> {
    let path = Path::new(&python);

    // If `python` is definitely a path, use it, if it exists.
    // For a path like 'foo/bar', .ancestors() returns "foo/bar", "foo", ""
    if path.is_absolute() || path.ancestors().take(3).count() == 3 {
        if path.exists() {
            return Ok(path.to_owned());
        } else {
            bail!("python not found at {}", path);
        }
    }

    let version_pattern = lazy_regex::regex!(r"^(\d)(\.(\d+))?$");
    if let Some(captures) = version_pattern.captures(&python) {
        let major = captures[1].parse().unwrap();
        let minor = captures.get(3).map(|n| n.as_str().parse().unwrap());

        return find_python_by_version(major, minor);
    }

    find_executable_in_path(python)
}

pub fn detect_from_version(python_version: crate::PythonVersion) -> EResult<PathBuf> {
    find_python_by_version(
        python_version.major.try_into().unwrap(),
        Some(python_version.minor.try_into().unwrap()),
    )
}

fn find_python_by_version(major: u32, minor: Option<u32>) -> EResult<PathBuf> {
    let version = match minor {
        Some(minor) => format!("{}.{}", major, minor),
        None => major.to_string(),
    };
    #[cfg(unix)]
    {
        find_executable_in_path(&format!("python{}", version))
    }

    #[cfg(windows)]
    {
        use color_eyre::section::{Section, SectionExt};
        let mut cmd = std::process::Command::new("py");
        cmd.args(&[
            &format!("-{}", version),
            "-c",
            "import sys; print(sys.executable)",
        ]);

        let output = cmd.output()?;

        let stdout = String::from_utf8(output.stdout)?;
        let path = Path::new(stdout.trim_end());
        if path.exists() {
            Ok(path.to_path_buf())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            Err(eyre!("can't find python version {}", version)
                .section(stdout.header("stdout"))
                .section(stderr.header("stderr")))
        }
    }
}

fn find_executable_in_path(path: impl AsRef<Path>) -> EResult<PathBuf> {
    let path = path.as_ref();
    let exe_path = pathsearch::find_executable_in_path(path)
        .ok_or_else(|| eyre!("couldn't find python executable `{}` in PATH", path))?;
    exe_path.try_into().wrap_err(INVALID_UTF8_PATH)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect() -> EResult<()> {
        detect("3").map(drop)
    }

    #[cfg(unix)]
    #[test]
    fn test_detect_by_number_and_by_name() -> EResult<()> {
        let python3_path = detect("python3")?;
        let python3_path2 = detect("3")?;

        assert_eq!(python3_path, python3_path2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_detect_with_minor_version() -> EResult<()> {
        // assuming you have python3 installed because this is 2020+.

        let python3_path = detect("python3")?;
        let python3_path2 = detect("3")?;

        assert_eq!(python3_path, python3_path2);

        // this upper boundary should last a while
        let path_with_minor = (5..30)
            .map(|minor| format!("3.{}", minor))
            .find_map(|version| detect(&version).ok())
            .unwrap();

        let path_with_minor2 = (5..30)
            .map(|minor| format!("python3.{}", minor))
            .find_map(|version| detect(&version).ok())
            .unwrap();

        assert_eq!(path_with_minor, path_with_minor2);
        Ok(())
    }
}
