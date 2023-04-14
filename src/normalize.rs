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

impl Normalize for IAMStatement {
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
                        ConditionValue::Str(OneOrMany::One(value)) => {
                            ConditionValue::Str(OneOrMany::Many(vec![value.clone()]))
                        }
                        ConditionValue::Str(OneOrMany::Many(value)) => {
                            ConditionValue::Str(OneOrMany::Many(value.clone()))
                        }
                        _ => condition_value.clone(),
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

impl Normalize for Principal {
    fn normalize(&self) -> Self {
        fn many(principals: &[String]) -> OneOrMany {
            let mut principals = principals.to_vec();
            principals.sort();
            principals.dedup();
            OneOrMany::Many(principals)
        }

        fn to_many(s: OneOrMany) -> OneOrMany {
            match s {
                OneOrMany::One(p) => many(&[p]),
                OneOrMany::Many(p) => many(&p),
            }
        }

        match self {
            Principal::Wildcard(_) => self.clone(),
            Principal::Principals(pb) => Self::Principals(PrincipalBlock {
                aws: pb.aws.clone().map(to_many),
                service: pb.service.clone().map(to_many),
                canonical_user: pb.canonical_user.clone().map(to_many),
                federated: pb.federated.clone().map(to_many),
            }),
        }
    }
}
