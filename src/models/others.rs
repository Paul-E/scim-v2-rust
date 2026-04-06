use serde::de::Deserializer;
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
pub enum Resource<T> {
    User(Box<User<T>>),
    Schema(Box<Schema>),
    Group(Box<Group<T>>),
    ResourceType(Box<ResourceType>),
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse<T> {
    pub items_per_page: i64,
    pub total_results: i64,
    pub start_index: i64,
    pub schemas: Vec<String>,
    #[serde(rename = "Resources")]
    pub resources: Vec<Resource<T>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PatchOp {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

#[derive(Serialize, Debug)]
#[serde(untagged)]
#[expect(clippy::large_enum_variant)]
pub enum OperationTarget {
    WithPath {
        path: PatchPath,
        value: Value,
    },
    WithoutPath {
        value: serde_json::Map<String, Value>,
    },
}

impl<'de> Deserialize<'de> for OperationTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut map = serde_json::Map::deserialize(deserializer)?;

        if let Some(path_value) = map.remove("path") {
            let path_str = path_value
                .as_str()
                .ok_or_else(|| serde::de::Error::custom("\"path\" must be a string"))?;
            let path: PatchPath = path_str
                .parse()
                .map_err(|e| serde::de::Error::custom(format!("invalid SCIM path: {e}")))?;
            let value = map.remove("value").unwrap_or(Value::Null);
            Ok(OperationTarget::WithPath { path, value })
        } else {
            let value = match map.remove("value") {
                Some(Value::Object(m)) => m,
                Some(_) => {
                    return Err(serde::de::Error::custom(
                        "\"value\" must be a JSON object when \"path\" is absent",
                    ))
                }
                None => {
                    return Err(serde::de::Error::missing_field("value"))
                }
            };
            Ok(OperationTarget::WithoutPath { value })
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op")]
pub enum PatchOperation {
    #[serde(rename = "add", alias = "Add", alias = "ADD")]
    Add(OperationTarget),
    #[serde(rename = "remove", alias = "Remove", alias = "REMOVE")]
    Remove {
        path: PatchPath,
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<Value>,
    },
    #[serde(rename = "replace", alias = "Replace", alias = "REPLACE")]
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
        match &ops.operations[0] {
            PatchOperation::Remove {
                path:
                    PatchPath::Value(PatchValuePath {
                        attr:
                            AttrPath {
                                uri: None,
                                name: attr_name,
                                sub_attr: None,
                            },
                        filter:
                            ValFilter::Attr(AttrExp::Comparison(
                                AttrPath {
                                    uri: None,
                                    name: inner_name,
                                    sub_attr: None,
                                },
                                CompareOp::Eq,
                                CompValue::Str(v),
                            )),
                        sub_attr: None,
                    }),
                value: None,
            } if attr_name == "members"
                && inner_name == "value"
                && v == "2819c223-7f76-...413861904646" => {}
            other => panic!("unexpected operation: {other:?}"),
        }
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
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None }),
                value: None,
            } if name == "members"
        ));
    }

    #[test]
    fn test_patch_op_05_remove_emails_compound_filter() {
        let ops: PatchOp = serde_json::from_str(include_str!("../test_data/operations_05.json"))
            .expect("Failed to deserialize patch operations");
        assert_eq!(ops.schemas, vec![PATCH_OP_SCHEMA]);
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Remove {
                path:
                    PatchPath::Value(PatchValuePath {
                        attr:
                            AttrPath {
                                uri: None,
                                name: attr_name,
                                sub_attr: None,
                            },
                        filter: ValFilter::And(left, right),
                        sub_attr: None,
                    }),
                value: None,
            } if attr_name == "emails" => {
                match left.as_ref() {
                    ValFilter::Attr(AttrExp::Comparison(
                        AttrPath {
                            uri: None,
                            name: n,
                            sub_attr: None,
                        },
                        CompareOp::Eq,
                        CompValue::Str(v),
                    )) if n == "type" && v == "work" => {}
                    other => panic!("unexpected left filter: {other:?}"),
                }
                match right.as_ref() {
                    ValFilter::Attr(AttrExp::Comparison(
                        AttrPath {
                            uri: None,
                            name: n,
                            sub_attr: None,
                        },
                        CompareOp::Ew,
                        CompValue::Str(v),
                    )) if n == "value" && v == "example.com" => {}
                    other => panic!("unexpected right filter: {other:?}"),
                }
            }
            other => panic!("unexpected operation: {other:?}"),
        }
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
                path: PatchPath::Attr(AttrPath { uri: None, name, sub_attr: None }),
                value: None,
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
                        filter:
                            ValFilter::Attr(AttrExp::Comparison(
                                AttrPath {
                                    uri: None,
                                    name: n,
                                    sub_attr: None,
                                },
                                CompareOp::Eq,
                                CompValue::Str(v),
                            )),
                        sub_attr: None,
                    }),
                ..
            }) if attr_name == "addresses" && n == "type" && v == "work" => {}
            other => panic!("unexpected operation: {other:?}"),
        }
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
                        filter:
                            ValFilter::Attr(AttrExp::Comparison(
                                AttrPath {
                                    uri: None,
                                    name: n,
                                    sub_attr: None,
                                },
                                CompareOp::Eq,
                                CompValue::Str(v),
                            )),
                        sub_attr: Some(sub_attr),
                    }),
                value,
            }) if attr_name == "addresses"
                && sub_attr == "streetAddress"
                && n == "type"
                && v == "work" =>
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

    // ---- Okta provider tests ----

    #[test]
    fn test_okta_replace_deactivate() {
        let ops: PatchOp =
            serde_json::from_str(include_str!("../test_data/okta_replace_deactivate.json"))
                .expect("Failed to deserialize Okta deactivation");
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Replace(OperationTarget::WithoutPath { value }) => {
                assert_eq!(value.get("active").and_then(|v| v.as_bool()), Some(false));
            }
            other => panic!("expected Replace WithoutPath, got {other:?}"),
        }
    }

    #[test]
    fn test_okta_add_members_array_value() {
        let ops: PatchOp =
            serde_json::from_str(include_str!("../test_data/okta_add_members.json"))
                .expect("Failed to deserialize Okta add members");
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Add(OperationTarget::WithPath { path, value }) => {
                assert_eq!(
                    path,
                    &PatchPath::Attr(AttrPath {
                        uri: None,
                        name: "members".into(),
                        sub_attr: None,
                    })
                );
                let arr = value.as_array().expect("value should be an array");
                assert_eq!(arr.len(), 1);
                assert_eq!(arr[0]["display"], "user@example.com");
                // Okta does NOT send "type" in member objects
                assert!(arr[0].get("type").is_none());
            }
            other => panic!("expected Add WithPath, got {other:?}"),
        }
    }

    #[test]
    fn test_okta_replace_members_array_value() {
        let ops: PatchOp =
            serde_json::from_str(include_str!("../test_data/okta_replace_members.json"))
                .expect("Failed to deserialize Okta replace members");
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Replace(OperationTarget::WithPath { path, value }) => {
                assert_eq!(
                    path,
                    &PatchPath::Attr(AttrPath {
                        uri: None,
                        name: "members".into(),
                        sub_attr: None,
                    })
                );
                let arr = value.as_array().expect("value should be an array");
                assert_eq!(arr.len(), 2);
            }
            other => panic!("expected Replace WithPath, got {other:?}"),
        }
    }

    // ---- JumpCloud provider tests ----

    #[test]
    fn test_jumpcloud_replace_user_fields() {
        let ops: PatchOp =
            serde_json::from_str(include_str!("../test_data/jumpcloud_replace_user_fields.json"))
                .expect("Failed to deserialize JumpCloud user field replace");
        assert_eq!(ops.operations.len(), 3);
        // JumpCloud sends one op per attribute with path
        match &ops.operations[0] {
            PatchOperation::Replace(OperationTarget::WithPath { path, value }) => {
                assert_eq!(
                    path,
                    &PatchPath::Attr(AttrPath {
                        uri: None,
                        name: "name".into(),
                        sub_attr: Some("givenName".into()),
                    })
                );
                assert_eq!(value.as_str(), Some("John"));
            }
            other => panic!("expected Replace WithPath for givenName, got {other:?}"),
        }
        // Third op: active = false (scalar bool value)
        match &ops.operations[2] {
            PatchOperation::Replace(OperationTarget::WithPath { path, value }) => {
                assert_eq!(
                    path,
                    &PatchPath::Attr(AttrPath {
                        uri: None,
                        name: "active".into(),
                        sub_attr: None,
                    })
                );
                assert_eq!(value.as_bool(), Some(false));
            }
            other => panic!("expected Replace WithPath for active, got {other:?}"),
        }
    }

    #[test]
    fn test_jumpcloud_add_member_minimal() {
        let ops: PatchOp =
            serde_json::from_str(include_str!("../test_data/jumpcloud_add_member.json"))
                .expect("Failed to deserialize JumpCloud add member");
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Add(OperationTarget::WithPath { value, .. }) => {
                let arr = value.as_array().expect("value should be an array");
                assert_eq!(arr.len(), 1);
                // JumpCloud sends minimal member objects: just "value", no display/type
                assert_eq!(arr[0]["value"], "jc-user-uuid-001");
                assert!(arr[0].get("display").is_none());
                assert!(arr[0].get("type").is_none());
            }
            other => panic!("expected Add WithPath, got {other:?}"),
        }
    }

    #[test]
    fn test_jumpcloud_remove_member_with_value() {
        let ops: PatchOp = serde_json::from_str(include_str!(
            "../test_data/jumpcloud_remove_member_with_value.json"
        ))
        .expect("Failed to deserialize JumpCloud remove member with value");
        assert_eq!(ops.operations.len(), 1);
        match &ops.operations[0] {
            PatchOperation::Remove {
                path,
                value: Some(v),
            } => {
                assert_eq!(
                    path,
                    &PatchPath::Attr(AttrPath {
                        uri: None,
                        name: "members".into(),
                        sub_attr: None,
                    })
                );
                let arr = v.as_array().expect("value should be an array");
                assert_eq!(arr[0]["value"], "jc-user-uuid-001");
            }
            other => panic!("expected Remove with value, got {other:?}"),
        }
    }

    // ---- Negative tests: malformed path must NOT silently fallthrough ----

    #[test]
    fn test_malformed_path_returns_error() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "emails[broken!!!filter",
                "value": {"displayName": "pwned"}
            }]
        }"#;
        let result: Result<PatchOp, _> = serde_json::from_str(json);
        assert!(result.is_err(), "malformed path must produce an error, not silently fallthrough");
    }

    #[test]
    fn test_invalid_op_returns_error() {
        let json = r#"{
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "delete", "path": "members"}]
        }"#;
        let result: Result<PatchOp, _> = serde_json::from_str(json);
        assert!(result.is_err(), "invalid op 'delete' must produce an error");
    }
}
