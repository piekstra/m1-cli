//! `m1f transfers list` — money movements: deposits, withdrawals, ACAT
//! transfers, and the like.
//!
//! This is the account-level cash-flow history (`viewer.transfers`), distinct
//! from `activity list`, which is per-account *investment* activity (trades,
//! dividends). Transfers are what move money in and out of M1.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{done_paging, emit, items, note_empty, paginate, table_view, Ctx};
use crate::{graphql, parse};

const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;

    let page_size = range.limit.map(|n| n.min(PAGE_SIZE)).unwrap_or(PAGE_SIZE);
    let mut cursor: Option<String> = None;
    let mut rows: Vec<Value> = Vec::new();
    let mut pages = 0usize;
    let mut truncated = false;

    loop {
        let vars = json!({ "first": page_size, "after": cursor });
        const PATH: &[&str] = &["viewer", "transfers", "pastInstances"];
        let data =
            ctx.read(|c| c.execute(graphql::TRANSFERS, vars.clone(), Some("TransfersHistory")))?;
        let container = parse::at(&data, PATH)?.clone();
        for node in parse::nodes(&data, PATH)? {
            rows.push(transfer_dto(&node)?);
        }
        pages += 1;

        let next = parse::next_cursor(&container);
        if next.is_some() && next == cursor {
            break;
        }
        cursor = next;
        // Transfers are newest-first, so once we hold enough to satisfy --limit
        // (with no --since to page further back for) there's nothing more.
        if cursor.is_none() || done_paging(range, &rows) {
            break;
        }
        if pages >= MAX_PAGES {
            truncated = true;
            break;
        }
    }
    if truncated && !ctx.common.quiet {
        eprintln!("stopped after {MAX_PAGES} pages — narrow with --since/--until or --limit");
    }

    let rows = paginate(rows, "date", range);
    if rows.is_empty() {
        note_empty(ctx, "transfers");
    }
    emit(
        ctx,
        "transfer-list",
        json!({ "items": rows, "truncated": truncated }),
        |v| {
            output::table(&table_view(
                &items(v, "items"),
                &["date", "status", "description", "amount"],
            ));
        },
    );
    Ok(())
}

fn transfer_dto(v: &Value) -> Result<Value, CliError> {
    let mut dto = json!({});
    // The node id is a `TransferInstance:{"transferId":…}` blob (credential-
    // shaped like documents); emit the stable inner id, not the raw blob.
    let raw_id = parse::id(v, "id")?;
    let id = parse::decode_relay_blob(&raw_id)
        .and_then(|inner| parse::opt_string(&inner, "transferId"))
        .unwrap_or(raw_id);
    dto["id"] = json!(id);

    // `startDate`/`endDate` are RFC 3339; a completed transfer is dated by when
    // it settled (`endDate`), falling back to when it started.
    if let Some(date) = parse::date_at(v, &["endDate", "startDate", "date"]) {
        dto["date"] = json!(date);
    }
    // `status` is an object; surface its `code` (COMPLETED / PENDING / …).
    if let Some(status) = v.get("status").and_then(|s| parse::opt_string(s, "code")) {
        dto["status"] = json!(status);
    }
    if let Some(desc) =
        parse::opt_string(v, "title").or_else(|| parse::opt_string(v, "description"))
    {
        dto["description"] = json!(desc);
    }
    if let Some(amount) = parse::money_at(v, "amount") {
        dto["amount"] = serde_json::to_value(amount).unwrap_or(Value::Null);
    }
    if v.get("isLiquidation") == Some(&Value::Bool(true)) {
        dto["is_liquidation"] = json!(true);
    }
    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_dto_maps_the_columns_and_decodes_the_id() {
        // Real shape: a TransferInstance:{transferId} base64 blob.
        // `VHJhbnNmZXJJbnN0YW5jZTp7InRyYW5zZmVySWQiOiJhYmMifQ==` decodes to
        // `TransferInstance:{"transferId":"abc"}`.
        let v = json!({
            "id": "VHJhbnNmZXJJbnN0YW5jZTp7InRyYW5zZmVySWQiOiJhYmMifQ==",
            "title": "External Bank to Individual Brokerage",
            "description": null,
            "amount": 500.0,
            "startDate": "2026-08-13T11:01:23.802Z",
            "endDate": "2026-08-13T13:29:37.762Z",
            "status": { "code": "COMPLETED", "isComplete": true }
        });
        let dto = transfer_dto(&v).unwrap();
        assert_eq!(dto["id"], json!("abc"));
        assert_eq!(dto["date"], json!("2026-08-13"));
        assert_eq!(dto["status"], json!("COMPLETED"));
        assert_eq!(
            dto["description"],
            json!("External Bank to Individual Brokerage")
        );
        assert_eq!(dto["amount"]["amount"], json!("500.00"));
        // The raw blob must not survive into the DTO.
        assert!(!serde_json::to_value(&dto)
            .unwrap()
            .to_string()
            .contains("VHJhbnNmZXI"));
    }

    #[test]
    fn a_withdrawal_keeps_its_negative_sign() {
        let dto = transfer_dto(&json!({ "id": "x", "amount": "-250.00" })).unwrap();
        assert_eq!(dto["amount"]["amount"], json!("-250.00"));
    }

    #[test]
    fn a_pending_transfer_shows_its_status() {
        let dto = transfer_dto(&json!({
            "id": "y", "title": "Deposit", "amount": 100.0,
            "status": { "code": "PENDING", "isPending": true }
        }))
        .unwrap();
        assert_eq!(dto["status"], json!("PENDING"));
    }

    #[test]
    fn a_missing_id_fails_loudly() {
        assert_eq!(
            transfer_dto(&json!({ "amount": 1.0 }))
                .unwrap_err()
                .exit_code(),
            5
        );
    }
}
