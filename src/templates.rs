//! Warrant templates: capabilities documents for common MCP servers with
//! named parameters.
//!
//! A template is JSON with a description, declared parameters, and a
//! capabilities document. A string equal to `${name}` becomes the parameter's
//! value (a list for list parameters); `${name}` inside a longer string is
//! replaced in place and takes only scalar parameters. Rendering is strict: a
//! missing, unknown, or unused parameter is an error, so a typo cannot leave a
//! constraint wider than intended.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Templates shipped with the CLI, by name.
pub const BUILTIN: &[(&str, &str)] = &[
    (
        "github-readonly",
        include_str!("../templates/github-readonly.json"),
    ),
    (
        "github-contributor",
        include_str!("../templates/github-contributor.json"),
    ),
    (
        "filesystem-readonly",
        include_str!("../templates/filesystem-readonly.json"),
    ),
    (
        "fetch-allowlist",
        include_str!("../templates/fetch-allowlist.json"),
    ),
    (
        "kubernetes-readonly",
        include_str!("../templates/kubernetes-readonly.json"),
    ),
    (
        "slack-channels",
        include_str!("../templates/slack-channels.json"),
    ),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub description: String,
    #[serde(default)]
    pub params: BTreeMap<String, Param>,
    pub capabilities: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Param {
    pub description: String,
    /// Comma-separated on the command line; substituted as a JSON array.
    #[serde(default)]
    pub list: bool,
}

impl Template {
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|error| format!("template: {error}"))
    }

    pub fn builtin(name: &str) -> Result<Self, String> {
        let (_, text) = BUILTIN
            .iter()
            .find(|(builtin, _)| *builtin == name)
            .ok_or_else(|| {
                let names: Vec<_> = BUILTIN.iter().map(|(name, _)| *name).collect();
                format!("unknown template {name}; available: {}", names.join(", "))
            })?;
        Self::parse(text)
    }

    /// Substitutes `values` (from `--param name=value`) into the capabilities.
    pub fn render(&self, values: &[(String, String)]) -> Result<Value, String> {
        let mut bound = BTreeMap::new();
        for (name, raw) in values {
            let param = self
                .params
                .get(name)
                .ok_or_else(|| format!("template has no parameter {name}"))?;
            let value = if param.list {
                let items: Vec<Value> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| Value::String(item.to_string()))
                    .collect();
                if items.is_empty() {
                    return Err(format!("parameter {name} needs at least one value"));
                }
                Value::Array(items)
            } else {
                if raw.is_empty() {
                    return Err(format!("parameter {name} must not be empty"));
                }
                Value::String(raw.clone())
            };
            if bound.insert(name.as_str(), value).is_some() {
                return Err(format!("parameter {name} given more than once"));
            }
        }
        if let Some(missing) = self
            .params
            .keys()
            .find(|name| !bound.contains_key(name.as_str()))
        {
            return Err(format!("missing parameter {missing}"));
        }
        let mut used = BTreeSet::new();
        let rendered = substitute(&self.capabilities, &bound, &mut used)?;
        if let Some(unused) = bound.keys().find(|name| !used.contains(*name)) {
            return Err(format!("template never uses parameter {unused}"));
        }
        Ok(rendered)
    }
}

/// Splits `name=value` from the command line.
pub fn parse_param(text: &str) -> Result<(String, String), String> {
    text.split_once('=')
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .ok_or_else(|| format!("expected name=value, got {text}"))
}

fn substitute<'a>(
    value: &Value,
    bound: &BTreeMap<&'a str, Value>,
    used: &mut BTreeSet<&'a str>,
) -> Result<Value, String> {
    Ok(match value {
        Value::String(text) => substitute_string(text, bound, used)?,
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| substitute(item, bound, used))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(fields) => {
            let mut out = Map::with_capacity(fields.len());
            for (key, item) in fields {
                if key.contains("${") {
                    return Err(format!("parameters are not allowed in keys: {key}"));
                }
                out.insert(key.clone(), substitute(item, bound, used)?);
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}

fn substitute_string<'a>(
    text: &str,
    bound: &BTreeMap<&'a str, Value>,
    used: &mut BTreeSet<&'a str>,
) -> Result<Value, String> {
    if let Some(name) = text
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
    {
        if !name.contains("${") && !name.contains('}') {
            let (key, value) = lookup(name, bound)?;
            used.insert(key);
            return Ok(value.clone());
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| format!("unclosed parameter in {text}"))?;
        let (key, value) = lookup(&after[..end], bound)?;
        let scalar = value.as_str().ok_or_else(|| {
            format!("list parameter {key} must be a whole value, not part of {text}")
        })?;
        used.insert(key);
        out.push_str(scalar);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(Value::String(out))
}

fn lookup<'a, 'b>(
    name: &str,
    bound: &'b BTreeMap<&'a str, Value>,
) -> Result<(&'a str, &'b Value), String> {
    bound
        .get_key_value(name)
        .map(|(key, value)| (*key, value))
        .ok_or_else(|| format!("template uses undeclared parameter {name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn template(capabilities: Value, params: Value) -> Template {
        serde_json::from_value(json!({
            "description": "test",
            "params": params,
            "capabilities": capabilities,
        }))
        .unwrap()
    }

    fn params(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn whole_values_take_lists_and_inline_values_take_scalars() {
        let t = template(
            json!({"t": {"repo": {"one_of": "${repos}"}, "path": {"subpath": "/srv/${dir}"}}}),
            json!({"repos": {"description": "r", "list": true}, "dir": {"description": "d"}}),
        );
        assert_eq!(
            t.render(&params(&[("repos", "a, b"), ("dir", "app")]))
                .unwrap(),
            json!({"t": {"repo": {"one_of": ["a", "b"]}, "path": {"subpath": "/srv/app"}}})
        );
    }

    #[test]
    fn rendering_is_strict() {
        let t = template(
            json!({"t": {"owner": "${owner}", "path": "/x/${owner}"}}),
            json!({"owner": {"description": "o"}, "repos": {"description": "r", "list": true}}),
        );
        for (given, expected) in [
            (vec![("owner", "a")], "missing parameter repos"),
            (
                vec![("owner", "a"), ("repos", "x"), ("typo", "y")],
                "no parameter typo",
            ),
            (
                vec![("owner", "a"), ("owner", "b"), ("repos", "x")],
                "more than once",
            ),
            (vec![("owner", ""), ("repos", "x")], "must not be empty"),
            (vec![("owner", "a"), ("repos", " , ")], "at least one value"),
            (
                vec![("owner", "a"), ("repos", "x")],
                "never uses parameter repos",
            ),
        ] {
            let error = t.render(&params(&given)).unwrap_err();
            assert!(error.contains(expected), "{given:?}: {error}");
        }

        let inline_list = template(
            json!({"t": {"path": "/x/${repos}"}}),
            json!({"repos": {"description": "r", "list": true}}),
        );
        assert!(inline_list
            .render(&params(&[("repos", "a")]))
            .unwrap_err()
            .contains("whole value"));
        let undeclared = template(json!({"t": {"a": "${nope}"}}), json!({}));
        assert!(undeclared.render(&[]).unwrap_err().contains("undeclared"));
        let in_key = template(
            json!({"t": {"${owner}": 1}}),
            json!({"owner": {"description": "o"}}),
        );
        assert!(in_key
            .render(&params(&[("owner", "a")]))
            .unwrap_err()
            .contains("keys"));
    }

    #[test]
    fn every_builtin_template_parses() {
        for (name, _) in BUILTIN {
            let t = Template::builtin(name).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(!t.description.is_empty(), "{name}");
        }
        assert!(Template::builtin("nope").unwrap_err().contains("available"));
    }

    #[test]
    fn params_split_on_the_first_equals() {
        assert_eq!(
            parse_param("query=a=b").unwrap(),
            ("query".to_string(), "a=b".to_string())
        );
        assert!(parse_param("=x").is_err());
        assert!(parse_param("x").is_err());
    }
}
