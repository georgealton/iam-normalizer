use crate::iam::*;

pub trait Normalize {
    fn normalize(&self) -> Self;
}

impl Normalize for ResourceBlock {
    fn normalize(&self) -> Self {
        fn many(resources: &[String]) -> OneOrMany {
            let mut resources = resources.to_vec();
            resources.sort();
            resources.dedup();
            OneOrMany::Many(resources)
        }

        fn one_or_many(one_or_many: &OneOrMany) -> OneOrMany {
            match one_or_many {
                OneOrMany::One(a) => many(&[a.clone()]),
                OneOrMany::Many(a) => many(a),
            }
        }

        match self {
            Self::Resource(resources) => Self::Resource(one_or_many(resources)),
            Self::NotResource(resources) => Self::NotResource(one_or_many(resources)),
        }
    }
}

impl Normalize for ActionBlock {
    fn normalize(&self) -> Self {
        fn many(actions: &[String]) -> OneOrMany {
            let mut actions: Vec<String> = actions.iter().map(|s| s.to_lowercase()).collect();
            actions.sort();
            actions.dedup();
            OneOrMany::Many(actions)
        }

        fn one_or_many(one_or_many: &OneOrMany) -> OneOrMany {
            match one_or_many {
                OneOrMany::One(a) => many(&[a.clone()]),
                OneOrMany::Many(a) => many(a),
            }
        }

        match self {
            Self::Action(actions) => Self::Action(one_or_many(actions)),
            Self::NotAction(actions) => Self::NotAction(one_or_many(actions)),
        }
    }
}

impl Normalize for PolicyDocument {
    fn normalize(&self) -> Self {
        Self {
            id: self.id.clone(),
            version: self.version.clone(),
            statement: self.statement.iter().map(Normalize::normalize).collect(),
        }
    }
}

impl Normalize for Statement {
    fn normalize(&self) -> Self {
        Self {
            sid: self.sid.clone(),
            effect: self.effect.clone(),
            action: self.action.normalize(),
            resource: self.resource.normalize(),
            condition: self.condition.clone().map(|c| c.normalize()),
            principal: self.principal.clone().map(|p| p.normalize()),
        }
    }
}

impl Normalize for ConditionKeyValue {
    fn normalize(&self) -> Self {
        self.iter()
            .map(|(condition_key, condition_value)| {
                (
                    condition_key.to_lowercase(),
                    match condition_value {
                        OneOrMany::One(value) => OneOrMany::Many(vec![value.clone()]),
                        OneOrMany::Many(value) => OneOrMany::Many(value.clone()),
                    },
                )
            })
            .collect()
    }
}

impl Normalize for ConditionMap {
    fn normalize(&self) -> Self {
        self.iter()
            .map(|(condition_operator, condition_key_value)| {
                (condition_operator.clone(), condition_key_value.normalize())
            })
            .collect()
    }
}

impl Normalize for PrincipalBlock {
    fn normalize(&self) -> Self {
        fn struct_or_string(principal_entry: &PrincipaMapOrId) -> PrincipaMapOrId {
            match principal_entry {
                PrincipaMapOrId::PrincipalMap(p) => PrincipaMapOrId::PrincipalMap(p.normalize()),
                PrincipaMapOrId::PrincipalId(_) => principal_entry.clone(),
            }
        }

        match self {
            Self::Principal(pb) => Self::Principal(struct_or_string(pb)),
            Self::NotPrincipal(pb) => Self::NotPrincipal(struct_or_string(pb)),
        }
    }
}

impl Normalize for PrincipalMap {
    fn normalize(&self) -> Self {
        fn many(principal_id: &[String]) -> OneOrMany {
            let mut principals = principal_id.to_vec();
            principals.sort();
            principals.dedup();
            OneOrMany::Many(principals)
        }

        fn to_many(principal_id: OneOrMany) -> OneOrMany {
            match principal_id {
                OneOrMany::One(p) => many(&[p]),
                OneOrMany::Many(p) => many(&p),
            }
        }

        Self {
            aws: self.aws.clone().map(to_many),
            service: self.service.clone().map(to_many),
            canonical_user: self.canonical_user.clone().map(to_many),
            federated: self.federated.clone().map(to_many),
        }
    }
}
