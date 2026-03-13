use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::group::Group;
use crate::models::resource_types::ResourceType;
use crate::models::scim_schema::Schema;
use crate::models::user::User;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SearchRequest {
    pub schemas: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    excluded_attributes: Option<Vec<String>>,
    pub filter: String,
    pub start_index: i64,
    pub count: i64,
}

impl Default for SearchRequest {
    fn default() -> Self {
        SearchRequest {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:SearchRequest".to_string()],
            attributes: None,
            excluded_attributes: None,
            filter: "".to_string(),
            start_index: 1,
            count: 100,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_index: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub excluded_attributes: Option<String>,
}

impl Default for ListQuery {
    fn default() -> Self {
        ListQuery {
            filter: Some("".to_string()),
            start_index: Some(1),
            count: Some(100),
            attributes: Some("".to_string()),
            excluded_attributes: Some("".to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Resource {
    User(Box<User>),
    Schema(Box<Schema>),
    Group(Box<Group>),
    ResourceType(Box<ResourceType>),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub items_per_page: i64,
    pub total_results: i64,
    pub start_index: i64,
    pub schemas: Vec<String>,
    #[serde(rename = "Resources")]
    pub resources: Vec<Resource>,
}

impl Default for ListResponse {
    fn default() -> Self {
        ListResponse {
            items_per_page: 0,
            total_results: 0,
            start_index: 1,
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
            resources: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PatchOp {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum OperationTarget {
    WithPath {
        path: String,
        value: Value,
    },
    WithoutPath {
        value: serde_json::Map<String, Value>,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op")]
pub enum PatchOperation {
    #[serde(rename = "add")]
    Add(OperationTarget),
    #[serde(rename = "remove")]
    Remove { path: String },
    #[serde(rename = "replace")]
    Replace(OperationTarget),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    #[test]
    fn test_deserialize_patch_op() {
        // operations_01.json: add members with one member value
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_01.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(
            matches!(&ops.operations[0], PatchOperation::Add(OperationTarget::WithPath { path, .. }) if path == "members")
        );

        // operations_02.json: add without path (whole-resource target)
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_02.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Add(OperationTarget::WithoutPath { .. })
        ));

        // operations_03.json: remove member by filter path
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_03.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(&ops.operations[0], PatchOperation::Remove { path }
                if path == "members[value eq \"2819c223-7f76-...413861904646\"]"));

        // operations_04.json: remove all members
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_04.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(&ops.operations[0], PatchOperation::Remove { path } if path == "members"));

        // operations_05.json: remove emails matching compound filter
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_05.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(&ops.operations[0], PatchOperation::Remove { path }
                if path == "emails[type eq \"work\" and value ew \"example.com\"]"));

        // operations_06.json: remove all members then add two new members
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_06.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 2);
        assert!(matches!(&ops.operations[0], PatchOperation::Remove { path } if path == "members"));
        assert!(
            matches!(&ops.operations[1], PatchOperation::Add(OperationTarget::WithPath { path, .. }) if path == "members")
        );

        // operations_07.json: replace members list
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_07.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(
            matches!(&ops.operations[0], PatchOperation::Replace(OperationTarget::WithPath { path, .. }) if path == "members")
        );

        // operations_08.json: replace work address with an object value
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_08.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(
            matches!(&ops.operations[0], PatchOperation::Replace(OperationTarget::WithPath { path, .. })
                if path == "addresses[type eq \"work\"]")
        );

        // operations_09.json: replace specific field via nested filter path
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_09.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Replace(OperationTarget::WithPath { path, value }) => {
                assert_eq!(path, "addresses[type eq \"work\"].streetAddress");
                assert_eq!(value.as_str(), Some("1010 Broadway Ave"));
            }
            _ => panic!("Expected Replace WithPath operation"),
        }

        // operations_10.json: replace without path (whole-resource target)
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_10.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Replace(OperationTarget::WithoutPath { .. })
        ));
    }
}
