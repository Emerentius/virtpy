use std::path::{Path, PathBuf};

pub fn detect(python: &str) -> Option<PathBuf> {
    let path = Path::new(&python);

    // If `python` is definitely a path, use it, if it exists.
    // For a path like 'foo/bar', .ancestors() returns "foo/bar", "foo", ""
    if path.is_absolute() || path.ancestors().take(3).count() == 3 {
        if path.exists() {
            return Some(path.to_owned());
        } else {
            return None;
        }
    }

    let version_pattern = regex::Regex::new(r"^(\d)(\.(\d+))?$").unwrap();
    if let Some(captures) = version_pattern.captures(&python) {
        let major = captures[1].parse().unwrap();
        let minor = captures.get(3).map(|n| n.as_str().parse().unwrap());

        return find_python_by_version(major, minor);
    }

    // FIXME: deal with that `py -<version>` situation on windows
    pathsearch::find_executable_in_path(&python)
}

fn find_python_by_version(major: u32, minor: Option<u32>) -> Option<PathBuf> {
    let version = match minor {
        Some(minor) => format!("{}.{}", major, minor),
        None => major.to_string(),
    };
    pathsearch::find_executable_in_path(&format!("python{}", version))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_detect() {
        // assuming you have python3 installed because this is 2020+.

        let python3_path = detect("python3").unwrap();
        let python3_path2 = detect("3").unwrap();

        assert_eq!(python3_path, python3_path2);

        // this upper boundary should last a while
        let path_with_minor = (5..30)
            .map(|minor| format!("3.{}", minor))
            .find_map(|version| detect(&version))
            .unwrap();

        let path_with_minor2 = (5..30)
            .map(|minor| format!("python3.{}", minor))
            .find_map(|version| detect(&version))
            .unwrap();

        assert_eq!(path_with_minor, path_with_minor2);
    }
}
