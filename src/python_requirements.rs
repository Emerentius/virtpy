use pest::Parser;
use std::process::Command;

#[derive(pest_derive::Parser)]
#[grammar = "requirements_txt.pest"] // relative to src
struct RequirementsTxtParser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub version: String,
    pub marker: Option<Marker>,
    pub available_hashes: Vec<crate::DependencyHash>,
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
                crate::DependencyHash(hash_token.into_inner().as_str().replace(":", "="))
            })
            .collect();

        Self {
            name,
            version,
            available_hashes,
            marker,
        }
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
pub fn get_requirements(package: &str) -> Vec<Requirement> {
    let tmp_dir = tempdir::TempDir::new("virtpy").unwrap();

    Command::new("poetry")
        .current_dir(&tmp_dir)
        .args(&["init", "-n"])
        .stdout(std::process::Stdio::null())
        .status()
        .expect("failed to run poetry init");

    // TODO: copy in a valid, minimal venv with pip.
    //       Otherwise poetry will create one (even though it's never used)
    //       and it will take multiple seconds.

    let toml_path = tmp_dir.as_ref().join("pyproject.toml");
    let mut doc = std::fs::read_to_string(&toml_path)
        .unwrap()
        .parse::<toml_edit::Document>()
        .unwrap();

    doc["tool"]["poetry"]["dependencies"][package] = toml_edit::value("*");
    std::fs::write(&toml_path, doc.to_string()).expect("failed to write pyproject.toml");

    // Tell poetry not to create a venv. Saves a lot of time.
    // Could also be done with `poetry config virtualenvs.create false --local`
    // but that's much slower.
    std::fs::write(
        tmp_dir.as_ref().join("poetry.toml"),
        "[virtualenvs]
create = false",
    )
    .unwrap();

    // Generating the poetry.lock file without actually installing anything.
    //
    // Alternatively, just calling `poetry export` will also create the lockfile without
    // installing anything, but it also emits a message telling you so. That message
    // can not be silenced and would have to be separated from the actual output.
    Command::new("poetry")
        .current_dir(&tmp_dir)
        .args(&["update", "--lock"])
        .stdout(std::process::Stdio::null())
        .status()
        .expect("failed to run poetry update");

    debug_assert!(tmp_dir.as_ref().join("poetry.lock").exists());

    let output = Command::new("poetry")
        .current_dir(&tmp_dir)
        .args(&["export", "-f", "requirements.txt"])
        .output()
        .expect("failed to run poetry export")
        .stdout;
    let output = std::str::from_utf8(&output).unwrap();

    read_requirements_txt(&output)
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
                    crate::DependencyHash(
                        "sha256:5b26757dc6f79a3b7dc9fab95359328d5747fcb2409d331ea66d0272b90ab2a0"
                            .into()
                    ),
                    crate::DependencyHash(
                        "sha256:8b995ffe925347a2138d7ac0fe77155e4311a0ea6d6da4f5128fe4b3cbe5ed71"
                            .into()
                    )
                ],
                    version: "0.1.0".into()
                },
                Requirement {
                    name: "backcall".into(),
                    marker: None,
                    available_hashes: vec![
                    crate::DependencyHash(
                        "sha256:fbbce6a29f263178a1f7915c1940bde0ec2b2a967566fe1c65c1dfb7422bd255"
                            .into()
                    ),
                    crate::DependencyHash(
                        "sha256:5cbdbf27be5e7cfadb448baf0aa95508f91f2bbc6c6437cd9cd06e2a4c215e1e"
                            .into()
                    )
                ],
                    version: "0.2.0".into()
                }
            ]
        );
    }
}
