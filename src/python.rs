use crate::{check_output, EResult, Path};
use eyre::eyre;
use eyre::Context;

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
