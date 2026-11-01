//! `m1f api query` — raw GraphQL passthrough, read-only.
//!
//! Shaped for GraphQL rather than the family's usual `api <METHOD> <PATH>`:
//! M1's backend is a single endpoint that only answers POST, so a method and a
//! path would both be noise. What varies is the document, its variables, and
//! (for multi-operation documents) which operation to run.
//!
//! Everything is guarded by `graphql::guard_read_only`, so a `mutation` cannot
//! reach a real brokerage account through this door.

use std::io::Read;

use pk_cli_core::{output, CliError};
use serde_json::Value;

use super::{emit, Ctx};
use crate::graphql;

#[derive(clap::Args, Debug)]
pub struct QueryArgs {
    /// The GraphQL query document, or `-` to read it from stdin.
    pub document: String,

    /// Variables as a JSON object, e.g. `--variables '{"id":"123"}'`.
    #[arg(long, value_name = "JSON")]
    pub variables: Option<String>,

    /// Which operation to run, for a document declaring more than one.
    #[arg(long, value_name = "NAME")]
    pub operation: Option<String>,
}

pub fn query(ctx: &Ctx, args: &QueryArgs) -> Result<(), CliError> {
    // Read stdin before anything else so a piped document is available to the
    // guard; validation happens before the keychain or network is touched.
    let document = if args.document == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| CliError::Usage(format!("reading the query from stdin: {e}")))?;
        buf
    } else {
        args.document.clone()
    };

    graphql::guard_read_only(&document)?;
    let variables = parse_variables(args.variables.as_deref())?;

    // With a stored session, ride the reauth rails. Without one, send the
    // query unauthenticated instead of refusing: the owner checklist's first
    // step probes the endpoint *before* any login (`{ __typename }`), and an
    // unauthenticated query risks nothing — M1 answers it with its own
    // UNAUTHENTICATED error if the operation needs a login.
    let payload = if ctx.tokens()?.is_some() {
        ctx.read(|c| c.execute(&document, variables.clone(), args.operation.as_deref()))?
    } else {
        ctx.anonymous()?
            .execute(&document, variables.clone(), args.operation.as_deref())?
    };
    emit(ctx, "graphql-response", payload, output::render);
    Ok(())
}

/// Parse `--variables`, requiring a JSON *object* — GraphQL variables are
/// always a map, and passing an array or scalar produces a confusing
/// server-side error rather than a clear local one.
fn parse_variables(raw: Option<&str>) -> Result<Value, CliError> {
    let Some(raw) = raw else {
        return Ok(Value::Object(Default::default()));
    };
    let v: Value = serde_json::from_str(raw)
        .map_err(|e| CliError::Usage(format!("--variables is not valid JSON: {e}")))?;
    if !v.is_object() {
        return Err(CliError::Usage(
            "--variables must be a JSON object, e.g. '{\"id\":\"123\"}'".into(),
        ));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn absent_variables_become_an_empty_object() {
        assert_eq!(parse_variables(None).unwrap(), json!({}));
    }

    #[test]
    fn an_object_is_accepted() {
        assert_eq!(
            parse_variables(Some(r#"{"id":"123"}"#)).unwrap(),
            json!({"id": "123"})
        );
    }

    #[test]
    fn non_objects_are_usage_errors() {
        for bad in [r#"["a"]"#, "42", r#""str""#] {
            let e = parse_variables(Some(bad)).unwrap_err();
            assert_eq!(e.exit_code(), 2, "{bad}");
            assert!(e.to_string().contains("JSON object"), "{bad}");
        }
    }

    #[test]
    fn malformed_json_is_a_usage_error_not_an_upstream_one() {
        let e = parse_variables(Some("{nope")).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains("not valid JSON"), "{e}");
    }
}
