use eyre::{bail, eyre, WrapErr};
use itertools::Itertools;
use std::path::PathBuf as StdPathBuf;

use crate::executables_path;
use crate::prelude::*;
use crate::{Path, PathBuf};

pub(crate) fn detect(python: &str) -> Result<PathBuf> {
    let path = Path::new(&python);

    // If `python` is definitely a path, use it, if it exists.
    // For a path like 'foo/bar', .ancestors() returns "foo/bar", "foo", ""
    if path.is_absolute() || path.ancestors().take(3).count() == 3 {
        if path.exists() {
            return Ok(path.to_owned());
        } else {
            bail!("python not found at {path}");
        }
    }

    let version_pattern = lazy_regex::regex!(r"^(\d)(\.(\d+))?$");
    if let Some(captures) = version_pattern.captures(python) {
        let major = captures[1].parse().unwrap();
        let minor = captures.get(3).map(|n| n.as_str().parse().unwrap());

        return find_python_by_version(major, minor);
    }

    find_executable_in_path(python)
}

pub(crate) fn detect_from_version(python_version: super::PythonVersion) -> Result<PathBuf> {
    find_python_by_version(python_version.major, Some(python_version.minor))
}

fn find_python_by_version(major: u32, minor: Option<u32>) -> Result<PathBuf> {
    let version = match minor {
        Some(minor) => format!("{major}.{minor}"),
        None => major.to_string(),
    };
    match crate::platform() {
        crate::Platform::Unix => find_executable_in_path(format!("python{version}")),
        crate::Platform::Windows => {
            use color_eyre::section::{Section, SectionExt};
            let mut cmd = std::process::Command::new("py");
            cmd.args([
                &format!("-{version}"),
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
}

fn find_executable_in_path(executable: impl AsRef<Path>) -> Result<PathBuf> {
    let executable = executable.as_ref();

    pathsearch::find_executable_in_path(executable)
        .ok_or_else(|| eyre!("couldn't find python executable `{executable}` in PATH"))?
        .try_into_utf8_pathbuf()
}

pub fn venvless_path() -> Result<Option<String>> {
    // If we're in an activated venv, the PATH has been modified
    // and we may find the executable in the venv's bin directory.
    // Remove the venv from the PATH in that case.
    // We need to use String instead of OsString because OsString
    // doesn't have any string modification methods.
    let path = std::env::var_os("PATH");
    let path = path
        .map(|path| {
            path.into_string()
                .map_err(|_| eyre!("PATH contains non-utf8 directories"))
        })
        .transpose()?;
    match (path, std::env::var_os("VIRTUAL_ENV")) {
        (Some(path), Some(venv_path)) => {
            let path_sep = match crate::platform() {
                crate::Platform::Unix => ":",
                crate::Platform::Windows => ";",
            };
            let venv_path = PathBuf::try_from(StdPathBuf::from(venv_path))
                .wrap_err("venv PATH is not valid utf8")?;
            let executables_dir = executables_path(&venv_path);
            Ok(Some(
                path.split(path_sep)
                    .filter(|&dir| Path::new(dir) != executables_dir)
                    .join(path_sep),
            ))
        }
        (path, _) => Ok(path),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect() -> Result<()> {
        detect("3").map(drop)
    }

    #[cfg(unix)]
    #[test]
    fn test_detect_by_number_and_by_name() -> Result<()> {
        let python3_path = detect("python3")?;
        let python3_path2 = detect("3")?;

        assert_eq!(python3_path, python3_path2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_detect_with_minor_version() -> Result<()> {
        // assuming you have python3 installed because this is 2020+.

        let python3_path = detect("python3")?;
        let python3_path2 = detect("3")?;

        assert_eq!(python3_path, python3_path2);

        // this upper boundary should last a while
        let path_with_minor = (5..30)
            .map(|minor| format!("3.{minor}"))
            .find_map(|version| detect(&version).ok())
            .unwrap();

        let path_with_minor2 = (5..30)
            .map(|minor| format!("python3.{minor}"))
            .find_map(|version| detect(&version).ok())
            .unwrap();

        assert_eq!(path_with_minor, path_with_minor2);
        Ok(())
    }
}
