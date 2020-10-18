use std::path::{Path, PathBuf};

pub fn detect(python: &str) -> eyre::Result<PathBuf> {
    let path = Path::new(&python);

    // If `python` is definitely a path, use it, if it exists.
    // For a path like 'foo/bar', .ancestors() returns "foo/bar", "foo", ""
    if path.is_absolute() || path.ancestors().take(3).count() == 3 {
        if path.exists() {
            return Ok(path.to_owned());
        } else {
            eyre::bail!("python not found at {}", path.display());
        }
    }

    let version_pattern = regex::Regex::new(r"^(\d)(\.(\d+))?$").unwrap();
    if let Some(captures) = version_pattern.captures(&python) {
        let major = captures[1].parse().unwrap();
        let minor = captures.get(3).map(|n| n.as_str().parse().unwrap());

        return find_python_by_version(major, minor);
    }

    // FIXME: deal with that `py -<version>` situation on windows
    find_executable_in_path(python)
}

fn find_python_by_version(major: u32, minor: Option<u32>) -> eyre::Result<PathBuf> {
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
            Err(eyre::eyre!("can't find python version {}", version).section(stdout.header("stdout")).section(stderr.header("stderr")))
        }
    }
}

fn find_executable_in_path(path: impl AsRef<Path>) -> eyre::Result<PathBuf> {
    let path = path.as_ref();
    pathsearch::find_executable_in_path(path).ok_or_else(|| eyre::eyre!("couldn't find python executable `{}` in PATH", path.display()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect() -> eyre::Result<()> {
        detect("3").map(drop)
    }

    #[cfg(unix)]
    #[test]
    fn test_detect_by_number_and_by_name() -> eyre::Result<()> {
        let python3_path = detect("python3")?;
        let python3_path2 = detect("3")?;

        assert_eq!(python3_path, python3_path2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_detect_with_minor_version() -> eyre::Result<()> {
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
