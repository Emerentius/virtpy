use pest::Parser;

#[derive(pest_derive::Parser)]
#[grammar = "requirements_txt.pest"] // relative to src
struct RequirementsTxtParser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub version: String,
    pub sys_condition: Option<SystemCondition>,
    pub available_hashes: Vec<crate::DependencyHash>,
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
    fn from_string(string: &str) -> Option<Self> {
        let mut parts = string.split_whitespace();
        let key = parts.next()?;
        if key != "sys_platform" {
            return None;
        }
        let condition = parts.next()?;
        let must_equal = condition == "==";
        if !must_equal && condition != "!=" {
            return None;
        }
        let system_name = parts.next()?.trim_matches('"').to_owned();
        Some(Self {
            must_equal,
            system_name,
        })
    }
}

impl Requirement {
    fn from_token(token: pest::iterators::Pair<Rule>) -> Self {
        assert_eq!(token.as_rule(), Rule::requirement);
        let mut subtokens = token.into_inner();
        let name = subtokens.next().unwrap().as_str().to_owned();
        let version = subtokens.next().unwrap().as_str().to_owned();
        let sys_condition = subtokens.next().unwrap().as_str().to_owned();

        // all remaining tokens are hashes
        let available_hashes = subtokens
            .map(|hash_token| {
                debug_assert_eq!(hash_token.as_rule(), Rule::hash);
                crate::DependencyHash(hash_token.into_inner().as_str().to_owned())
            })
            .collect();

        Self {
            name,
            version,
            available_hashes,
            sys_condition: SystemCondition::from_string(&sys_condition),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_equal_system_condition() {
        let system_condition = "sys_platform == \"darwin\"";
        assert_eq!(
            SystemCondition::from_string(system_condition),
            Some(SystemCondition {
                must_equal: true,
                system_name: "darwin".into(),
            })
        );
    }

    #[test]
    fn test_parse_not_equal_system_condition() {
        let system_condition = "sys_platform != \"win32\"";
        assert_eq!(
            SystemCondition::from_string(system_condition),
            Some(SystemCondition {
                must_equal: false,
                system_name: "win32".into(),
            })
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
                    sys_condition: Some(SystemCondition {
                        must_equal: true,
                        system_name: "darwin".into()
                    }),
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
                    sys_condition: None,
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

fn foo() {
    [
        Requirement {
            name: "appnope".into(),
            version: "0.1.0".into(),
            sys_condition: Some(SystemCondition {
                must_equal: true,
                system_name: "darwin".into(),
            }),
            available_hashes: vec![
                crate::DependencyHash(
                    "sha256:5b26757dc6f79a3b7dc9fab95359328d5747fcb2409d331ea66d0272b90ab2a0"
                        .into(),
                ),
                crate::DependencyHash(
                    "sha256:8b995ffe925347a2138d7ac0fe77155e4311a0ea6d6da4f5128fe4b3cbe5ed71"
                        .into(),
                ),
            ],
        },
        Requirement {
            name: "backcall".into(),
            version: "0.2.0".into(),
            sys_condition: None,
            available_hashes: vec![
                crate::DependencyHash(
                    "sha256:fbbce6a29f263178a1f7915c1940bde0ec2b2a967566fe1c65c1dfb7422bd255"
                        .into(),
                ),
                crate::DependencyHash(
                    "sha256:5cbdbf27be5e7cfadb448baf0aa95508f91f2bbc6c6437cd9cd06e2a4c215e1e"
                        .into(),
                ),
            ],
        },
    ];
    [Requirement {
        name: "appnope".into(),
        version: "0.1.0".into(),
        sys_condition: Some(SystemCondition {
            must_equal: true,
            system_name: "darwin".into(),
        }),
        available_hashes: vec![
            crate::DependencyHash(
                "sha256:5b26757dc6f79a3b7dc9fab95359328d5747fcb2409d331ea66d0272b90ab2a0".into(),
            ),
            crate::DependencyHash(
                "sha256:8b995ffe925347a2138d7ac0fe77155e4311a0ea6d6da4f5128fe4b3cbe5ed71".into(),
            ),
        ],
    }];
}
