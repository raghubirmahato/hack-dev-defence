//! `profile schema|check` (T-0006 step 3, tests): keeps `docs/profile.schema.json` and `hdd.live.example.yaml` in step with the
//! profile types of `hdd-common`.
//!
//! * the schema file must equal the schema generated from the types (regenerate with `profile schema`);
//! * the example file must parse strictly, must document every non-array field of the schema, and must fail validation only for
//!   the fields that are intentionally empty in an example (so a drifting example cannot hide a new failure).

use std::collections::BTreeSet;
use std::path::Path;

use hdd_common::profile::{self, Context, Status};
use serde_json::Value;

use crate::util::{Finding, Result, read_text, write_text};

/// Failures the example file is expected to show: (rule, field). Everything else must pass.
pub const EXPECTED_EXAMPLE_FAILURES: &[(&str, &str)] = &[
    ("PROF-REQUIRED", "operator_email"),
    ("PROF-REQUIRED", "acme.email"),
];

fn resolve<'a>(root: &'a Value, node: &'a Value) -> &'a Value {
    if let Some(r) = node.get("$ref").and_then(Value::as_str)
        && let Some(name) = r.strip_prefix("#/$defs/")
        && let Some(def) = root.get("$defs").and_then(|d| d.get(name))
    {
        return def;
    }
    node
}

/// Dotted paths of every object field in the schema (arrays are leaves).
pub fn schema_paths(schema: &Value) -> BTreeSet<String> {
    fn walk(root: &Value, node: &Value, prefix: &str, out: &mut BTreeSet<String>, depth: usize) {
        if depth > 12 {
            return;
        }
        let node = resolve(root, node);
        if let Some(props) = node.get("properties").and_then(Value::as_object) {
            for (k, v) in props {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.insert(path.clone());
                walk(root, v, &path, out, depth + 1);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(schema, schema, "", &mut out, 0);
    out
}

/// Dotted paths of every key in the example (arrays are leaves).
pub fn value_paths(v: &Value) -> BTreeSet<String> {
    fn walk(node: &Value, prefix: &str, out: &mut BTreeSet<String>) {
        if let Some(map) = node.as_object() {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                out.insert(path.clone());
                walk(v, &path, out);
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(v, "", &mut out);
    out
}

/// `profile schema`: write `docs/profile.schema.json`.
pub fn write_schema(root: &Path) -> Result<()> {
    write_text(
        &root.join("docs").join("profile.schema.json"),
        &profile::schema_json(),
    )?;
    write_text(
        &root.join("docs").join("runtime-env.schema.json"),
        &profile::env::schema_json(),
    )?;
    println!("profile schema: wrote docs/profile.schema.json and docs/runtime-env.schema.json");
    Ok(())
}

/// `profile check`: schema and example are current.
pub fn check(root: &Path) -> Vec<Finding> {
    let mut f = Vec::new();
    match read_text(&root.join("docs").join("profile.schema.json")) {
        Ok(cur) if cur == profile::schema_json() => {}
        Ok(_) => f.push(Finding::new("profile", "docs/profile.schema.json", "differs from the schema generated from hdd-common::profile::Profile; run `cargo xtask profile schema`")),
        Err(e) => f.push(Finding::new("profile", "docs/profile.schema.json", e.0)),
    }
    match read_text(&root.join("docs").join("runtime-env.schema.json")) {
        Ok(cur) if cur == profile::env::schema_json() => {}
        Ok(_) => f.push(Finding::new("profile", "docs/runtime-env.schema.json", "differs from the schema generated from hdd-common::profile::env::RuntimeEnv; run `cargo xtask profile schema`")),
        Err(e) => f.push(Finding::new("profile", "docs/runtime-env.schema.json", e.0)),
    }
    let example = match read_text(&root.join("hdd.live.example.yaml")) {
        Ok(t) => t,
        Err(e) => {
            f.push(Finding::new("profile", "hdd.live.example.yaml", e.0));
            return f;
        }
    };
    let schema: Value = match serde_json::from_str(&profile::schema_json()) {
        Ok(v) => v,
        Err(e) => {
            f.push(Finding::new(
                "profile",
                "docs/profile.schema.json",
                format!("generated schema is not JSON: {e}"),
            ));
            return f;
        }
    };
    match profile::parse_value(&example) {
        Ok(raw) => {
            let documented = value_paths(&raw);
            for path in schema_paths(&schema) {
                if !documented.contains(&path) {
                    f.push(Finding::new("profile", "hdd.live.example.yaml", format!("field `{path}` is defined by the schema but not documented in the example file")));
                }
            }
        }
        Err(e) => f.push(Finding::new(
            "profile",
            "hdd.live.example.yaml",
            e.to_string(),
        )),
    }
    match profile::parse_yaml(&example) {
        Ok(p) => {
            let report = profile::validate(&p, &Context::default());
            let got: BTreeSet<(String, String)> = report
                .findings
                .iter()
                .filter(|x| x.status == Status::Fail)
                .map(|x| (x.rule.to_owned(), x.field.clone()))
                .collect();
            let want: BTreeSet<(String, String)> = EXPECTED_EXAMPLE_FAILURES
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect();
            for (rule, field) in got.difference(&want) {
                f.push(Finding::new(
                    "profile",
                    "hdd.live.example.yaml",
                    format!("unexpected {rule} failure on `{field}`"),
                ));
            }
            for (rule, field) in want.difference(&got) {
                f.push(Finding::new("profile", "hdd.live.example.yaml", format!("expected {rule} failure on `{field}` is gone (update EXPECTED_EXAMPLE_FAILURES or restore the empty value)")));
            }
        }
        Err(e) => f.push(Finding::new(
            "profile",
            "hdd.live.example.yaml",
            e.to_string(),
        )),
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_paths_list_nested_object_fields_and_treat_arrays_as_leaves() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {"a": {"$ref": "#/$defs/A"}, "list": {"type": "array", "items": {"$ref": "#/$defs/A"}}},
            "$defs": {"A": {"type": "object", "properties": {"b": {"type": "string"}, "c": {"$ref": "#/$defs/C"}}}, "C": {"type": "object", "properties": {"d": {"type": "integer"}}}}
        });
        let paths: Vec<String> = schema_paths(&schema).into_iter().collect();
        assert_eq!(paths, vec!["a", "a.b", "a.c", "a.c.d", "list"]);
    }

    #[test]
    fn value_paths_follow_mappings_only() {
        let v = serde_json::json!({"a": {"b": 1, "c": [ {"x": 1} ]}, "d": "s"});
        let paths: Vec<String> = value_paths(&v).into_iter().collect();
        assert_eq!(paths, vec!["a", "a.b", "a.c", "d"]);
    }

    #[test]
    fn generated_schema_is_valid_json_with_the_expected_top_level_fields() {
        let schema: Value = serde_json::from_str(&profile::schema_json()).expect("json");
        let paths = schema_paths(&schema);
        for p in [
            "schema_version",
            "runtime.local.ports.web",
            "origin.tls_verify.mode",
            "egress_allowlist",
            "app_inventory.patch_sla_days.kev",
        ] {
            assert!(paths.contains(p), "{p}");
        }
    }
}
