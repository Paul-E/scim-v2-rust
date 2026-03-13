# CHANGELOG

## 0.4

- **Breaking** - Refactor `PatchOperation` to be closer to format specified in rfc7644
- Add SCIM filter expression parser (`filter` module, RFC 7644 §3.4.2.2) with AST types (`Filter`, `PatchPath`, `AttrExp`, `AttrPath`, `CompareOp`, `CompValue`, `ValFilter`, `ValuePath`) and `FromStr`/`Display`/serde support; `SearchRequest` and `ListQuery` now include an optional `filter` field

## 0.3

- Add `externalId` to user and group entities
- **Breaking** - Uses raw identifiers, converting `type_` to `r#type`
