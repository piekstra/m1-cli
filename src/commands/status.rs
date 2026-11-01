//! `m1f status` — M1's own system status, without spending a credential.
//!
//! This is the cheap first probe: it distinguishes "M1 is down" (or degraded,
//! or in maintenance) from "your session died" before anyone reaches for
//! `auth login`. The query is unauthenticated by design, so it touches neither
//! the keychain nor a stored token.

use pk_cli_core::{output, CliError};
use serde_json::{json, Value};

use super::{emit, Ctx};
use crate::{graphql, parse};

pub fn show(ctx: &Ctx) -> Result<(), CliError> {
    let client = ctx.anonymous()?;
    let data = client.execute(graphql::SYSTEM_STATUS, json!({}), Some("SystemStatus"))?;
    let dto = status_dto(parse::at(&data, &["system"])?)?;
    emit(ctx, "system-status", dto, output::render);
    Ok(())
}

/// Map a `SystemInfo` object to the `system-status/v1` DTO.
///
/// Pure so it can be contract-tested offline against a fixture, like every
/// other read shape. `status` is a `SystemStatusEnum` (NORMAL / DEGRADED /
/// DISRUPTED / MAINTENANCE); a non-NORMAL status is M1's state honestly
/// reported, not a failure of this tool, so the caller keeps exit 0. An empty
/// object is the interesting failure branch — it means the shape changed.
fn status_dto(sys: &Value) -> Result<Value, CliError> {
    let mut dto = json!({});
    if let Some(status) = parse::opt_string(sys, "status") {
        dto["status"] = json!(status);
    }
    if let Some(msg) = parse::opt_string(sys, "statusMessage") {
        dto["message"] = json!(msg);
    }
    if let Some(blocking) = sys.get("isStatusBlocking").and_then(|b| b.as_bool()) {
        dto["blocking"] = json!(blocking);
    }
    if let Some(version) = parse::opt_string(sys, "version") {
        dto["api_version"] = json!(version);
    }
    if dto.as_object().is_some_and(|m| m.is_empty()) {
        return Err(CliError::Upstream(
            "M1 answered the status query with an empty object — the shape may have changed".into(),
        ));
    }
    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_dto_maps_the_system_info_fields() {
        let sys = json!({
            "status": "NORMAL",
            "statusMessage": null,
            "isStatusBlocking": false,
            "version": "2.158.172"
        });
        let dto = status_dto(&sys).unwrap();
        assert_eq!(dto["status"], json!("NORMAL"));
        assert_eq!(dto["blocking"], json!(false));
        assert_eq!(dto["api_version"], json!("2.158.172"));
        // A null statusMessage is omitted, not rendered as an empty string.
        assert!(dto.get("message").is_none());
    }

    #[test]
    fn a_maintenance_message_is_surfaced() {
        let sys = json!({
            "status": "MAINTENANCE",
            "statusMessage": "Scheduled maintenance until 02:00 ET",
            "isStatusBlocking": true
        });
        let dto = status_dto(&sys).unwrap();
        assert_eq!(dto["status"], json!("MAINTENANCE"));
        assert_eq!(dto["blocking"], json!(true));
        assert_eq!(
            dto["message"],
            json!("Scheduled maintenance until 02:00 ET")
        );
    }

    #[test]
    fn an_empty_system_object_is_a_loud_upstream_error() {
        let err = status_dto(&json!({})).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
