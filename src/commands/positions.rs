//! `m1f positions list` — every position across the household's accounts, in
//! the family's `position-list/v1` shape (the one `schw`, `rhd` and `alp`
//! answer), so a consumer reads M1 with the same per-symbol reader.
//!
//! Where `holdings list` is M1's own rich per-account view, this is the
//! cross-provider surface: rows lead with `symbol`/`quantity`/`market_value`
//! and carry the account facts (`account_id`, `account_name`, `account_type`,
//! `registration`, `is_retirement`) so a tax consumer can tell a taxable
//! position from a retirement one, and a traditional IRA from a Roth IRA.
//! `account_type` is the family spelling of the registration
//! (`ira_traditional`, `ira_roth`, `individual`, … — robinhood-cli's
//! vocabulary; `accounts::family_type`). It spans every account unless `--account`/`M1F_ACCOUNT`
//! names one; the config default account is deliberately NOT consulted, so a
//! household capture cannot be silently narrowed by a convenience setting.

use pk_cli_core::{output, CliError};
use serde_json::{json, Value};

use super::{accounts, emit, holdings, items, note_empty, table_view, Ctx};
use crate::parse;

/// `positions list` flags. A position is a point-in-time reading with no
/// date, so the range flags other lists take would be accepted and ignored;
/// only `--limit` applies.
#[derive(clap::Args, Debug, Default)]
pub struct ListArgs {
    /// Return at most N positions.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

pub fn list(ctx: &Ctx, args: &ListArgs) -> Result<(), CliError> {
    let accts = accounts::scope(ctx, ctx.household_selection())?;
    let mut rows = accounts::rows_across(&accts, |acct| {
        holdings::fetch_nodes(ctx, &acct.id)?
            .iter()
            .map(position_row)
            .collect()
    })?;
    if let Some(n) = args.limit {
        rows.truncate(n as usize);
    }
    if rows.is_empty() {
        note_empty(ctx, "positions");
    }
    emit(ctx, "position-list", json!({ "items": rows }), |v| {
        output::table(&table_view(
            &items(v, "items"),
            &[
                "symbol",
                "quantity",
                "market_value",
                "cost_basis",
                "account_name",
                "account_type",
            ],
        ));
    });
    Ok(())
}

/// One family position row from an M1 position node.
///
/// Built on `holdings::holding_dto` so the two views cannot disagree on a
/// figure, then renamed to the family spelling (`value` → `market_value`,
/// `avg_price` → `average_price`). The node `id` is a relay blob
/// (`Position:{"accountId":…,"cusip":…}`, observed live 2026-09-23); the row
/// carries the decoded `cusip`, never the blob.
pub(crate) fn position_row(node: &Value) -> Result<Value, CliError> {
    let h = holdings::holding_dto(node)?;
    let symbol = h
        .get("symbol")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Upstream("an M1 position arrived with no symbol".into()))?;
    let mut row = json!({ "symbol": symbol });
    for (from, to) in [
        ("quantity", "quantity"),
        ("value", "market_value"),
        ("cost_basis", "cost_basis"),
        ("avg_price", "average_price"),
        ("unrealized_gain", "unrealized_gain"),
        ("name", "name"),
    ] {
        if let Some(v) = h.get(from) {
            row[to] = v.clone();
        }
    }
    if let Some(cusip) = node
        .get("id")
        .and_then(Value::as_str)
        .and_then(parse::decode_relay_blob)
        .and_then(|b| parse::opt_string(&b, "cusip"))
    {
        row["cusip"] = json!(cusip);
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_row_leads_with_symbol_and_uses_the_family_spelling() {
        let node = json!({
            // The live shape: base64 of `Position:{"accountId":"acct-000000001","cusip":"00000DUMMY"}`.
            "id": "UG9zaXRpb246eyJhY2NvdW50SWQiOiJhY2N0LTAwMDAwMDAwMSIsImN1c2lwIjoiMDAwMDBEVU1NWSJ9",
            "quantity": 2.5,
            "value": { "value": 300.0, "priceDate": "2026-09-22" },
            "cost": { "cost": 250.0, "averageSharePrice": 100.0 },
            "security": { "symbol": "VTI", "name": "Dummy Total Market ETF" }
        });
        let row = position_row(&node).unwrap();
        let keys: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys[0], "symbol");
        assert_eq!(row["quantity"], json!("2.5"));
        assert_eq!(row["market_value"]["amount"], json!("300.00"));
        assert_eq!(row["cost_basis"]["amount"], json!("250.00"));
        assert_eq!(row["average_price"]["amount"], json!("100.00"));
        assert_eq!(row["cusip"], json!("00000DUMMY"));
        assert!(
            row.get("id").is_none(),
            "the relay blob must not be emitted"
        );
        assert!(row.get("value").is_none());
    }

    /// The household read stamps each row with its account's family type, so
    /// a consumer places a rollover IRA (registered TRADITIONAL_IRA) in Form
    /// 8606 line 6 and a Roth IRA out of it without knowing M1's enum.
    #[test]
    fn household_rows_carry_each_accounts_family_type() {
        let acct = |id: &str, name: &str, reg: &str| accounts::AccountRef {
            id: id.into(),
            name: Some(name.into()),
            registration: Some(reg.into()),
            is_retirement: reg.ends_with("_IRA"),
        };
        let accts = vec![
            acct("acct-000000001", "Rollover", "TRADITIONAL_IRA"),
            acct("acct-000000002", "Roth", "ROTH_IRA"),
            acct("acct-000000003", "Taxable", "INDIVIDUAL"),
        ];
        let rows = accounts::rows_across(&accts, |_| {
            Ok(vec![position_row(&json!({
                "id": "x", "quantity": 1,
                "value": { "value": 10.0 },
                "security": { "symbol": "VTI" }
            }))?])
        })
        .unwrap();
        let types: Vec<&str> = rows
            .iter()
            .map(|r| r["account_type"].as_str().unwrap())
            .collect();
        assert_eq!(types, ["ira_traditional", "ira_roth", "individual"]);
        assert_eq!(rows[0]["registration"], json!("TRADITIONAL_IRA"));
        assert_eq!(rows[0]["account_name"], json!("Rollover"));
    }

    #[test]
    fn a_position_without_a_symbol_fails_loudly() {
        let err = position_row(&json!({ "id": "x", "quantity": 1 })).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn an_undecodable_id_just_omits_the_cusip() {
        let row = position_row(&json!({ "id": "plain", "security": { "symbol": "X" } })).unwrap();
        assert!(row.get("cusip").is_none());
    }
}
