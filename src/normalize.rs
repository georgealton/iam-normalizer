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

        match self {
            Self::Resource(OneOrMany::One(r)) => Self::Resource(many(&[r.clone()])),
            Self::Resource(OneOrMany::Many(r)) => Self::Resource(many(r)),
            Self::NotResource(OneOrMany::One(r)) => Self::NotResource(many(&[r.clone()])),
            Self::NotResource(OneOrMany::Many(r)) => Self::NotResource(many(r)),
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

        match self {
            Self::Action(OneOrMany::One(a)) => Self::Action(many(&[a.clone()])),
            Self::Action(OneOrMany::Many(a)) => Self::Action(many(a)),
            Self::NotAction(OneOrMany::One(a)) => Self::NotAction(many(&[a.clone()])),
            Self::NotAction(OneOrMany::Many(a)) => Self::NotAction(many(a)),
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
        match self {
            PrincipalBlock::String => self.clone(),
            PrincipalBlock::Principal(principal_map) => Self::Principal(principal_map.normalize()),
            PrincipalBlock::NotPrincipal(principal_map) => {
                Self::NotPrincipal(principal_map.normalize())
            }
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
