use eyre::{eyre, WrapErr};
use pest::Parser;
use std::{path::Path, process::Command};

use crate::{DistributionHash, EResult};

#[derive(pest_derive::Parser)]
#[grammar = "requirements_txt.pest"] // relative to src
struct RequirementsTxtParser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub version: String,
    pub marker: Option<Marker>,
    pub available_hashes: Vec<crate::DistributionHash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Marker {
    SystemCondition(SystemCondition),
    Unknown(String),
}

impl Marker {
    pub fn matches_system(&self) -> bool {
        match self {
            Marker::SystemCondition(cond) => cond.matches_system(),
            Marker::Unknown(_) => true, // let pip sort it out
        }
    }
}

impl std::fmt::Display for Marker {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Marker::SystemCondition(cond) => write!(f, "{}", cond),
            Marker::Unknown(string) => write!(f, "{}", string),
        }
    }
}

fn sys_platform() -> String {
    // https://docs.python.org/3/library/sys.html#sys.platform
    // OS            |  sys.platform
    // -----------------------------
    // AIX              'aix'
    // Linux            'linux'
    // Windows          'win32'
    // Windows/Cygwin   'cygwin'
    // macOS            'darwin'

    // will probably have to have to call out to python to do this right

    #[cfg(target_os = "windows")]
    {
        "win32".to_owned()
    }

    #[cfg(target_os = "linux")]
    {
        "linux".to_owned()
    }

    #[cfg(target_os = "macos")]
    {
        "darwin".to_owned()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemCondition {
    // "must equal" or "must not equal"
    must_equal: bool,
    system_name: String,
}

impl SystemCondition {
    pub fn matches_system(&self) -> bool {
        if self.must_equal {
            self.system_name == sys_platform()
        } else {
            self.system_name != sys_platform()
        }
    }
}

impl std::fmt::Display for SystemCondition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "sys_platform {} \"{}\"",
            if self.must_equal { "==" } else { "!=" },
            self.system_name
        )
    }
}

impl SystemCondition {
    fn from_string(string: &str) -> Self {
        let mut parts = string.split_whitespace();
        let key = parts.next().unwrap();
        debug_assert!(key == "sys_platform");
        let condition = parts.next().unwrap();
        let must_equal = condition == "==";
        debug_assert!(must_equal || condition == "!=");
        let system_name = parts.next().unwrap().trim_matches('"').to_owned();
        Self {
            must_equal,
            system_name,
        }
    }

    fn from_token(token: pest::iterators::Pair<Rule>) -> Self {
        Self::from_string(token.as_str())
    }
}

impl Requirement {
    fn from_token(token: pest::iterators::Pair<Rule>) -> Self {
        assert_eq!(token.as_rule(), Rule::requirement);
        let mut subtokens = token.into_inner();
        let name = subtokens.next().unwrap().as_str().to_owned();
        let version = subtokens.next().unwrap().as_str().to_owned();
        let marker = subtokens.next().unwrap();
        let marker = match marker.clone().into_inner().next() {
            Some(pair) => Some(Marker::SystemCondition(SystemCondition::from_token(pair))),
            None if marker.as_str().is_empty() => None,
            None => Some(Marker::Unknown(
                marker
                    .as_str()
                    .trim_start_matches(&[' ', ';'][..])
                    .to_owned(),
            )),
        };

        // all remaining tokens are hashes
        let available_hashes = subtokens
            .map(|hash_token| {
                debug_assert_eq!(hash_token.as_rule(), Rule::hash);

                // TODO: split hash type and hash into separate values
                crate::DistributionHash(hash_token.into_inner().as_str().replace(":", "="))
            })
            .collect();

        Self {
            name,
            version,
            available_hashes,
            marker,
        }
    }

    pub fn from_filename(filename: &str, hash: DistributionHash) -> EResult<Self> {
        // TODO: use a better parser
        let (_, name, version, _, _) =
            lazy_regex::regex_captures!(r"^([\w\d]+)-(\d+(\.\d+)*)(\.tar\.gz|.*\.whl)", filename)
                .unwrap();

        Ok(Requirement {
            name: name.to_owned(),
            version: version.to_owned(),
            marker: None,
            available_hashes: vec![hash],
        })
        //RequirementsTxtParser::parse(Rule::wheel_name, wheel_name).unwrap();
    }
}

pub fn read_requirements_txt(data: &str) -> Vec<Requirement> {
    let mut tokens = RequirementsTxtParser::parse(Rule::requirements, data)
        .unwrap_or_else(|err| panic!("{}", err));
    let requirements = tokens.next().unwrap();

    requirements
        .into_inner()
        .map(Requirement::from_token)
        .collect()
}

// Meant for installation of single packages with executables
// into a self-contained venv, like pipx does.
pub fn get_requirements(package: &str, allow_prereleases: bool) -> EResult<Vec<Requirement>> {
    fn init_temporary_poetry_project(
        package: &str,
        allow_prereleases: bool,
    ) -> EResult<tempdir::TempDir> {
        let tmp_dir = tempdir::TempDir::new("virtpy").unwrap();

        crate::check_output(
            Command::new("poetry")
                .current_dir(&tmp_dir)
                .args(&["init", "-n"])
                .stdout(std::process::Stdio::null()),
        )
        .wrap_err("failed to init poetry project")?;

        let toml_path = tmp_dir.as_ref().join("pyproject.toml");
        let mut doc = fs_err::read_to_string(&toml_path)?
            .parse::<toml_edit::Document>()
            .wrap_err("failed to parse pyproject.toml")?;

        let mut dep_table = toml_edit::Table::new();
        dep_table["version"] = toml_edit::value("*");
        if allow_prereleases {
            dep_table["allow-prereleases"] = toml_edit::value(true);
        }
        doc["tool"]["poetry"]["dependencies"][package] = toml_edit::Item::Table(dep_table);
        fs_err::write(&toml_path, doc.to_string())
            .wrap_err_with(|| eyre!("failed to add {} to pyproject.toml", package))?;
        Ok(tmp_dir)
    }

    let tmp_dir = init_temporary_poetry_project(package, allow_prereleases)
        .wrap_err("failed to create temporary poetry project")?;

    poetry_get_requirements(tmp_dir.as_ref(), false).wrap_err_with(|| {
        eyre!(
            "failed to get requirements for {} from poetry (allow_prereleases = {})",
            package,
            allow_prereleases
        )
    })
}

pub fn poetry_get_requirements(
    poetry_proj: &Path,
    include_dev_dependencies: bool,
) -> EResult<Vec<Requirement>> {
    poetry_deactivate_venv_creation(poetry_proj);

    // Generating the poetry.lock file without actually installing anything.
    //
    // Alternatively, just calling `poetry export` will also create the lockfile without
    // installing anything, but it also emits a message telling you so. That message
    // can not be silenced and would have to be separated from the actual output.
    crate::check_output(
        Command::new("poetry")
            .current_dir(poetry_proj)
            .args(&["update", "--lock"])
            .stdout(std::process::Stdio::null()),
    )?;

    debug_assert!(poetry_proj.join("poetry.lock").exists());

    let mut command = Command::new("poetry");
    command
        .current_dir(poetry_proj)
        .args(&["export", "-f", "requirements.txt"]);

    if include_dev_dependencies {
        command.arg("--dev");
    }

    let output = crate::check_output(&mut command).wrap_err("failed to get requirements.txt")?;

    Ok(read_requirements_txt(&output))
}

/// Poetry creates venvs automatically which not only takes a lot of time, it may
/// also create them in poetry's global directory.
fn poetry_deactivate_venv_creation(poetry_proj: &Path) {
    // Manually read the poetry.toml and set the appropriate setting.
    // Could also be done with `poetry config virtualenvs.create false --local`
    // but that's much slower, because poetry is a typical python project
    // that imports EVERYTHING at startup.
    let toml_path = poetry_proj.join("poetry.toml");
    let mut doc = match fs_err::read_to_string(&toml_path) {
        Ok(string) => string,
        Err(err) if crate::is_not_found(&err) => "[virtualenvs]".to_owned(),
        Err(err) => panic!("failed to read poetry.toml: {}", err),
    }
    .parse::<toml_edit::Document>()
    .unwrap();

    doc["virtualenvs"]["create"] = toml_edit::value(false);
    fs_err::write(&toml_path, doc.to_string()).expect("failed to write poetry.toml");
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_equal_system_condition() {
        let system_condition = "sys_platform == \"darwin\"";
        assert_eq!(
            SystemCondition::from_string(system_condition),
            SystemCondition {
                must_equal: true,
                system_name: "darwin".into(),
            }
        );
    }

    #[test]
    fn test_parse_not_equal_system_condition() {
        let system_condition = "sys_platform != \"win32\"";
        assert_eq!(
            SystemCondition::from_string(system_condition),
            SystemCondition {
                must_equal: false,
                system_name: "win32".into(),
            }
        );
    }

    #[test]
    fn test_parse_requirements() {
        let data = include_str!("../test_files/requirements.txt");
        let requirements = read_requirements_txt(data);

        assert_eq!(
            requirements,
            vec![
                Requirement {
                    name: "appnope".into(),
                    marker: Some(Marker::SystemCondition(SystemCondition {
                        must_equal: true,
                        system_name: "darwin".into()
                    })),
                    available_hashes: vec![
                    crate::DistributionHash(
                        "sha256=5b26757dc6f79a3b7dc9fab95359328d5747fcb2409d331ea66d0272b90ab2a0"
                            .into()
                    ),
                    crate::DistributionHash(
                        "sha256=8b995ffe925347a2138d7ac0fe77155e4311a0ea6d6da4f5128fe4b3cbe5ed71"
                            .into()
                    )
                ],
                    version: "0.1.0".into()
                },
                Requirement {
                    name: "backcall".into(),
                    marker: None,
                    available_hashes: vec![
                    crate::DistributionHash(
                        "sha256=fbbce6a29f263178a1f7915c1940bde0ec2b2a967566fe1c65c1dfb7422bd255"
                            .into()
                    ),
                    crate::DistributionHash(
                        "sha256=5cbdbf27be5e7cfadb448baf0aa95508f91f2bbc6c6437cd9cd06e2a4c215e1e"
                            .into()
                    )
                ],
                    version: "0.2.0".into()
                }
            ]
        );
    }

    #[test]
    fn test_parse_wheel_name_into_requirement() {
        #[rustfmt::skip]
        let filenames_and_output = [
            ("astroid-2.4.2-py3-none-any.whl", ("astroid", "2.4.2")),
            ("async_generator-1.10-py3-none-any.whl", ("async_generator", "1.10")),
            ("attrs-19.3.0-py2.py3-none-any.whl", ("attrs", "19.3.0")),
            ("click-7.1.2-py2.py3-none-any.whl", ("click", "7.1.2")),
            ("idna-3.1-py3-none-any.whl", ("idna", "3.1")),
            ("isort-4.3.21-py2.py3-none-any.whl", ("isort", "4.3.21")),
            ("lazy_object_proxy-1.4.3-cp38-cp38-manylinux1_x86_64.whl", ("lazy_object_proxy", "1.4.3")),
            ("mccabe-0.6.1-py2.py3-none-any.whl", ("mccabe", "0.6.1")),
            ("more_itertools-8.4.0-py3-none-any.whl", ("more_itertools", "8.4.0")),
            ("mypy-0.782-cp38-cp38-manylinux1_x86_64.whl", ("mypy", "0.782")),
            ("mypy_extensions-0.4.3-py2.py3-none-any.whl", ("mypy_extensions", "0.4.3")),
            ("outcome-1.1.0-py2.py3-none-any.whl", ("outcome", "1.1.0")),
            ("packaging-20.4-py2.py3-none-any.whl", ("packaging", "20.4")),
            ("pluggy-0.13.1-py2.py3-none-any.whl", ("pluggy", "0.13.1")),
            ("py-1.8.2-py2.py3-none-any.whl", ("py", "1.8.2")),
            ("pylint-2.5.3-py3-none-any.whl", ("pylint", "2.5.3")),
            ("pyparsing-2.4.7-py2.py3-none-any.whl", ("pyparsing", "2.4.7")),
            ("pytest-5.4.3-py3-none-any.whl", ("pytest", "5.4.3")),
            ("six-1.15.0-py2.py3-none-any.whl", ("six", "1.15.0")),
            ("sniffio-1.2.0-py3-none-any.whl", ("sniffio", "1.2.0")),
            ("sortedcontainers-2.4.0-py2.py3-none-any.whl", ("sortedcontainers", "2.4.0")),
            ("toml-0.10.1-py2.py3-none-any.whl", ("toml", "0.10.1")),
            ("trio-0.18.0-py3-none-any.whl", ("trio", "0.18.0")),
            ("typed_ast-1.4.1-cp38-cp38-manylinux1_x86_64.whl", ("typed_ast", "1.4.1")),
            ("typing_extensions-3.7.4.2-py3-none-any.whl", ("typing_extensions", "3.7.4.2")),
            ("wcwidth-0.2.5-py2.py3-none-any.whl", ("wcwidth", "0.2.5")),
            ("wrapt-1.12.1.tar.gz", ("wrapt", "1.12.1")),
        ];

        for &(filename, (distrib_name, version)) in filenames_and_output.iter() {
            let req = Requirement::from_filename(filename, DistributionHash("".into())).unwrap();
            assert_eq!(req.name, distrib_name);
            assert_eq!(req.version, version);
        }
    }
}
