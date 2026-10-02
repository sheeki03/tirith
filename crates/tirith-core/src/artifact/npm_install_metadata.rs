//! Exact npm 11.19.0 hidden-lock metadata for the closed local-leaf contract.
//!
//! Values come from retained manifests and the launcher's actual input layout.
//! A lockfile is never accepted based solely on npm's exit code or its own hash.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{NpmInstallRefusal, Result};

pub(super) const MAX_HIDDEN_LOCK_BYTES: usize = 128 * 1024;
const MAX_LEAF_METADATA_BYTES: usize = 8 * 1024;

pub(super) fn capture_leaf_metadata(
    object: &Map<String, Value>,
    name: &str,
) -> Result<BTreeMap<String, Value>> {
    // npm can discover bin paths from this directory declaration. This contract
    // admits only explicit bin values whose normalization is fully modelled.
    if object
        .get("directories")
        .and_then(Value::as_object)
        .is_some_and(|directories| directories.contains_key("bin"))
    {
        return Err(NpmInstallRefusal::ManifestUnsupported);
    }
    let mut fields = BTreeMap::new();
    for field in [
        "funding",
        "engines",
        "os",
        "cpu",
        "libc",
        "deprecated",
        "license",
    ] {
        let Some(value) = object.get(field) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let value = match field {
            "engines"
                if value
                    .as_object()
                    .is_some_and(|map| map.values().all(Value::is_string)) =>
            {
                value.clone()
            }
            "os" | "cpu" | "libc"
                if value
                    .as_array()
                    .is_some_and(|values| values.iter().all(Value::is_string)) =>
            {
                value.clone()
            }
            "deprecated" if value.is_string() => value.clone(),
            "license" if value.is_string() => value.clone(),
            "license"
                if value
                    .as_object()
                    .and_then(|map| map.get("type"))
                    .is_some_and(Value::is_string) =>
            {
                value["type"].clone()
            }
            "funding" if value.is_string() || value.is_object() || value.is_array() => {
                value.clone()
            }
            _ => return Err(NpmInstallRefusal::ManifestUnsupported),
        };
        // Arborist metaFieldFromPkg omits falsey values and empty collections.
        let present = match &value {
            Value::String(value) => !value.is_empty(),
            Value::Array(value) => !value.is_empty(),
            Value::Object(value) => !value.is_empty(),
            _ => return Err(NpmInstallRefusal::ManifestUnsupported),
        };
        if present {
            fields.insert(field.to_owned(), value);
        }
    }
    if let Some(bin) = object.get("bin") {
        let mut normalized = Map::new();
        match bin {
            Value::String(target) if !target.is_empty() => {
                let key = name.rsplit('/').next().expect("validated package name");
                normalized.insert(key.into(), Value::String(normalize_bin_target(target)?));
            }
            Value::Object(bins) => {
                for (key, value) in bins {
                    // Restrict keys to the already-normalized subset. Multiple
                    // authored keys collapsing to one output must not alias.
                    if key.is_empty()
                        || key.len() > 214
                        || key.starts_with('.')
                        || !key
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
                    {
                        return Err(NpmInstallRefusal::ManifestUnsupported);
                    }
                    let target = value
                        .as_str()
                        .ok_or(NpmInstallRefusal::ManifestUnsupported)?;
                    normalized.insert(key.clone(), Value::String(normalize_bin_target(target)?));
                }
            }
            Value::Null => (),
            Value::String(target) if target.is_empty() => (),
            _ => return Err(NpmInstallRefusal::ManifestUnsupported),
        }
        if !normalized.is_empty() {
            fields.insert("bin".into(), Value::Object(normalized));
        }
    }
    if object
        .get("scripts")
        .and_then(Value::as_object)
        .is_some_and(|scripts| {
            ["preinstall", "install", "postinstall"]
                .iter()
                .any(|event| {
                    scripts
                        .get(*event)
                        .and_then(Value::as_str)
                        .is_some_and(|script| !script.is_empty())
                })
        })
    {
        fields.insert("hasInstallScript".into(), Value::Bool(true));
    }
    if serde_json::to_vec(&fields)
        .map_err(|_| NpmInstallRefusal::ManifestUnsupported)?
        .len()
        > MAX_LEAF_METADATA_BYTES
    {
        return Err(NpmInstallRefusal::ResourceLimit);
    }
    Ok(fields)
}

fn normalize_bin_target(target: &str) -> Result<String> {
    let target = target.strip_prefix("./").unwrap_or(target);
    if target.is_empty()
        || target.len() > 4096
        || target.contains(['\\', ':', '\0'])
        || target
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(NpmInstallRefusal::ManifestUnsupported);
    }
    Ok(target.to_owned())
}

/// `resolved` must be derived by the retained launch-layout binding. This pure
/// helper does not authorize a path or construct an execution capability.
pub(super) fn leaf_row(
    version: &str,
    integrity: &str,
    resolved: &str,
    metadata: &BTreeMap<String, Value>,
) -> Value {
    let mut row: Map<String, Value> = metadata.clone().into_iter().collect();
    row.insert("version".into(), Value::String(version.into()));
    row.insert("resolved".into(), Value::String(resolved.into()));
    row.insert("integrity".into(), Value::String(integrity.into()));
    Value::Object(row)
}

pub(super) fn verify_hidden_lock(bytes: &[u8], expected: &Value) -> Result<()> {
    if bytes.len() > MAX_HIDDEN_LOCK_BYTES {
        return Err(NpmInstallRefusal::ResourceLimit);
    }
    let text =
        std::str::from_utf8(bytes).map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
    let value = crate::mcp_lock::parse_json_no_duplicates(text)
        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
    if &value != expected {
        return Err(NpmInstallRefusal::InstalledContentChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_native_npm_metadata_matches_the_complete_characterized_rows() {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/npm/install/hidden-lock-11.19.0.json"
        ))
        .unwrap();
        for case in corpus["cases"].as_array().unwrap() {
            let manifest = case["manifest"].as_object().unwrap();
            let fields =
                capture_leaf_metadata(manifest, manifest["name"].as_str().unwrap()).unwrap();
            let actual = leaf_row(
                manifest["version"].as_str().unwrap(),
                case["row"]["integrity"].as_str().unwrap(),
                case["row"]["resolved"].as_str().unwrap(),
                &fields,
            );
            assert_eq!(actual, case["row"], "{}", case["fixture"]);
            let expected = serde_json::json!({"lockfileVersion":3,"requires":true,
                "packages":{format!("node_modules/{}", manifest["name"].as_str().unwrap()):actual}});
            verify_hidden_lock(&serde_json::to_vec_pretty(&expected).unwrap(), &expected).unwrap();
        }
    }

    #[test]
    fn changed_origin_integrity_graph_unknown_fields_and_duplicate_keys_refuse() {
        let expected = serde_json::json!({"lockfileVersion":3,"requires":true,"packages":{
            "node_modules/leaf":{"version":"1.0.0","resolved":"file:../inputs/npm-abc.tgz","integrity":"sha512-bound"}}});
        for pointer in [
            "/packages/node_modules~1leaf/resolved",
            "/packages/node_modules~1leaf/integrity",
        ] {
            let mut altered = expected.clone();
            *altered.pointer_mut(pointer).unwrap() = Value::String("changed".into());
            assert!(verify_hidden_lock(&serde_json::to_vec(&altered).unwrap(), &expected).is_err());
        }
        let mut altered = expected.clone();
        altered["packages"]["node_modules/hidden"] = serde_json::json!({"version":"1.0.0"});
        assert!(verify_hidden_lock(&serde_json::to_vec(&altered).unwrap(), &expected).is_err());
        altered = expected.clone();
        altered["unrecognized"] = Value::Bool(true);
        assert!(verify_hidden_lock(&serde_json::to_vec(&altered).unwrap(), &expected).is_err());
        assert!(verify_hidden_lock(
            br#"{"lockfileVersion":2,"lockfileVersion":3,"requires":true,"packages":{}}"#,
            &expected
        )
        .is_err());
        assert_eq!(
            verify_hidden_lock(&vec![b' '; MAX_HIDDEN_LOCK_BYTES + 1], &expected),
            Err(NpmInstallRefusal::ResourceLimit)
        );
    }

    #[test]
    fn unmodelled_bin_normalization_and_directory_discovery_refuse() {
        for bin in [
            serde_json::json!({"../alias":"cli.js"}),
            serde_json::json!({"tool":"../cli.js"}),
            serde_json::json!(["cli.js"]),
        ] {
            let manifest = serde_json::json!({"bin":bin});
            assert!(capture_leaf_metadata(manifest.as_object().unwrap(), "leaf").is_err());
        }
        let manifest = serde_json::json!({"directories":{"bin":"bin"}});
        assert!(capture_leaf_metadata(manifest.as_object().unwrap(), "leaf").is_err());
    }
}
