use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[skip_serializing_none]
#[derive(Deserialize, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    pub version: Option<String>,
    pub id: Option<String>,
    pub statement: Vec<Statement>,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PrincipalMap {
    #[serde(rename = "AWS")]
    pub aws: Option<OneOrMany>,
    pub service: Option<OneOrMany>,
    pub federated: Option<OneOrMany>,
    pub canonical_user: Option<OneOrMany>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum PrincipaMapOrId {
    PrincipalMap(PrincipalMap),
    PrincipalId(String),
}

#[derive(Deserialize, Serialize, Clone)]
pub enum PrincipalBlock {
    Principal(PrincipaMapOrId),
    NotPrincipal(PrincipaMapOrId),
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize, Serialize, Clone)]
pub enum ActionBlock {
    Action(OneOrMany),
    NotAction(OneOrMany),
}

#[derive(Deserialize, Serialize, Clone)]
pub enum ResourceBlock {
    Resource(OneOrMany),
    NotResource(OneOrMany),
}

type ConditionType = String;
type ConditionKey = String;
pub type ConditionValue = OneOrMany;
pub type ConditionMap = HashMap<ConditionType, ConditionKeyValue>;
pub type ConditionKeyValue = HashMap<ConditionKey, ConditionValue>;

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Statement {
    pub sid: Option<String>,
    pub effect: String,
    #[serde(flatten)]
    pub principal: Option<PrincipalBlock>,
    #[serde(flatten)]
    pub action: ActionBlock,
    #[serde(flatten)]
    pub resource: ResourceBlock,
    pub condition: Option<ConditionMap>,
}

pub fn load_policy(policy: &str) -> Result<PolicyDocument, serde_json::error::Error> {
    serde_json::from_str::<PolicyDocument>(policy)
}
