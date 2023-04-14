use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use std::collections::HashMap;

#[skip_serializing_none]
#[derive(Deserialize, Clone, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct PolicyDocument {
    pub id: Option<String>,
    pub version: Option<String>,
    pub statement: Vec<IAMStatement>,
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct PrincipalBlock {
    #[serde(rename = "AWS")]
    pub aws: Option<OneOrMany>,
    pub service: Option<OneOrMany>,
    pub federated: Option<OneOrMany>,
    pub canonical_user: Option<OneOrMany>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum Principal {
    Wildcard(String),
    Principals(PrincipalBlock),
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum ActionBlock {
    Action(OneOrMany),
    NotAction(OneOrMany),
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum ResourceBlock {
    Resource(OneOrMany),
    NotResource(OneOrMany),
}

type ConditionOperator = String;
type ConditionKey = String;
pub type ConditionMap = HashMap<ConditionOperator, ConditionKeyValue>;
pub type ConditionKeyValue = HashMap<ConditionKey, ConditionValue>;

#[derive(Deserialize, Serialize, Clone)]
#[serde(untagged)]
pub enum ConditionValue {
    Str(OneOrMany),
    Num(serde_json::Number),
    Bool(bool),
}

#[skip_serializing_none]
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct IAMStatement {
    pub sid: Option<String>,
    pub effect: String,
    pub principal: Option<Principal>,
    pub action: ActionBlock,
    pub resource: ResourceBlock,
    pub condition: Option<ConditionMap>,
}

pub fn load_policy(policy: &str) -> Result<PolicyDocument, serde_json::error::Error> {
    serde_json::from_str::<PolicyDocument>(policy)
}
