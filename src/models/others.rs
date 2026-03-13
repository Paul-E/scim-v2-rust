use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::filter::{Filter, PatchPath};
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
    pub start_index: i64,
    pub count: i64,
}

impl Default for SearchRequest {
    fn default() -> Self {
        SearchRequest {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:SearchRequest".to_string()],
            attributes: None,
            excluded_attributes: None,
            filter: None,
            start_index: 1,
            count: 100,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
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
            filter: None,
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
        path: PatchPath,
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
    Remove { path: PatchPath },
    #[serde(rename = "replace")]
    Replace(OperationTarget),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{
        AttrExp, AttrPath, CompValue, CompareOp, PatchPath, PatchValuePath, ValFilter,
    };
    use pretty_assertions::assert_eq;

    const PATCH_OP_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

    #[test]
    fn test_patch_op_01_add_with_path() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_01.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Add(OperationTarget::WithPath {
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None }),
                ..
            }) if name == "members"
        ));
    }

    #[test]
    fn test_patch_op_02_add_without_path() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_02.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Add(OperationTarget::WithoutPath { .. })
        ));
    }

    #[test]
    fn test_patch_op_03_remove_member_by_filter() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_03.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Remove {
                path: PatchPath::Value(PatchValuePath {
                    attr: AttrPath { uri: None, name: attr_name, sub_attr: None },
                    filter,
                    sub_attr: None,
                })
            } if attr_name == "members"
              && matches!(
                  filter.as_ref(),
                  ValFilter::Attr(AttrExp::Comparison(
                      AttrPath { uri: None, name: inner_name, sub_attr: None },
                      CompareOp::Eq,
                      CompValue::Str(v),
                  )) if inner_name == "value" && v == "2819c223-7f76-...413861904646"
              )
        ));
    }

    #[test]
    fn test_patch_op_04_remove_all_members() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_04.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Remove {
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None })
            } if name == "members"
        ));
    }

    #[test]
    fn test_patch_op_05_remove_emails_compound_filter() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_05.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Remove {
                path: PatchPath::Value(PatchValuePath {
                    attr: AttrPath { uri: None, name: attr_name, sub_attr: None },
                    filter,
                    sub_attr: None,
                })
            } if attr_name == "emails"
              && matches!(
                  filter.as_ref(),
                  ValFilter::And(left, right)
                  if matches!(
                      left.as_ref(),
                      ValFilter::Attr(AttrExp::Comparison(
                          AttrPath { uri: None, name: n, sub_attr: None },
                          CompareOp::Eq,
                          CompValue::Str(v),
                      )) if n == "type" && v == "work"
                  ) && matches!(
                      right.as_ref(),
                      ValFilter::Attr(AttrExp::Comparison(
                          AttrPath { uri: None, name: n, sub_attr: None },
                          CompareOp::Ew,
                          CompValue::Str(v),
                      )) if n == "value" && v == "example.com"
                  )
              )
        ));
    }

    #[test]
    fn test_patch_op_06_remove_then_add_members() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_06.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 2);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Remove {
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None })
            } if name == "members"
        ));
        assert!(matches!(
            &ops.operations[1],
            PatchOperation::Add(OperationTarget::WithPath {
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None }),
                ..
            }) if name == "members"
        ));
    }

    #[test]
    fn test_patch_op_07_replace_members_list() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_07.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Replace(OperationTarget::WithPath {
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None }),
                ..
            }) if name == "members"
        ));
    }

    #[test]
    fn test_patch_op_08_replace_work_address() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_08.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        assert!(matches!(
            &ops.operations[0],
            PatchOperation::Replace(OperationTarget::WithPath {
                path: PatchPath::Value(PatchValuePath {
                    attr: AttrPath { uri: None, name: attr_name, sub_attr: None },
                    filter,
                    sub_attr: None,
                }),
                ..
            }) if attr_name == "addresses"
              && matches!(
                  filter.as_ref(),
                  ValFilter::Attr(AttrExp::Comparison(
                      AttrPath { uri: None, name: n, sub_attr: None },
                      CompareOp::Eq,
                      CompValue::Str(v),
                  )) if n == "type" && v == "work"
              )
        ));
    }

    #[test]
    fn test_patch_op_09_replace_street_address_via_filter() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_09.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Replace(OperationTarget::WithPath {
                path:
                    PatchPath::Value(PatchValuePath {
                        attr:
                            AttrPath {
                                uri: None,
                                name: attr_name,
                                sub_attr: None,
                            },
                        filter,
                        sub_attr: Some(sub_attr),
                    }),
                value,
            }) if attr_name == "addresses"
                && sub_attr == "streetAddress"
                && matches!(
                    filter.as_ref(),
                    ValFilter::Attr(AttrExp::Comparison(
                        AttrPath { uri: None, name: n, sub_attr: None },
                        CompareOp::Eq,
                        CompValue::Str(v),
                    )) if n == "type" && v == "work"
                ) =>
            {
                assert_eq!(value.as_str(), Some("1010 Broadway Ave"));
            }
            _ => panic!("Expected Replace WithPath for addresses[type eq \"work\"].streetAddress"),
        }
    }

    #[test]
    fn test_patch_op_10_replace_without_path() {
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
