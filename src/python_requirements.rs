use pest::Parser;

#[derive(pest_derive::Parser)]
#[grammar = "requirements_txt.pest"] // relative to src
struct RequirementsTxtParser;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub name: String,
    pub version: String,
    pub sys_condition: String,
    pub available_hashes: Vec<crate::DependencyHash>,
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
            sys_condition,
        }
    }
}

pub fn read_requirements_txt(data: String) -> Vec<Requirement> {
    let mut tokens = RequirementsTxtParser::parse(Rule::requirements, &data)
        .unwrap_or_else(|err| panic!("{}", err));
    let requirements = tokens.next().unwrap();

    requirements
        .into_inner()
        .map(Requirement::from_token)
        .collect()
}
