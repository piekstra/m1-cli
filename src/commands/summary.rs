//! `m1f summary` — a per-account financial snapshot.
//!
//! One screen per account: total value and cash, the investment cost basis and
//! market value, the unrealized gain (dollars **and** percent — the "how is
//! this account doing" number nothing else surfaces), and lifetime funding
//! (deposits vs withdrawals by year). Household-wide net worth is `net-worth`;
//! this is the account-level view.

use pk_cli_core::{output, CliError};
use serde_json::{json, Value};

use super::{emit, items, table_view, Ctx};
use crate::{graphql, parse};

pub fn show(ctx: &Ctx) -> Result<(), CliError> {
    let account = ctx.account()?;
    let data = ctx.read(|c| {
        c.execute(
            graphql::ACCOUNT_SUMMARY,
            json!({ "accountId": account }),
            Some("AccountSummary"),
        )
    })?;
    parse::require_node(&data)?;
    let dto = summary_dto(parse::at(&data, &["node"])?)?;

    emit(ctx, "account-summary", dto, |v| {
        let mut head = serde_json::Map::new();
        for k in [
            "name",
            "registration",
            "total_value",
            "cash",
            "invested_cost",
            "market_value",
            "unrealized_gain",
            "gain_percent",
            "gain_is_partial",
        ] {
            if let Some(val) = v.get(k) {
                head.insert(k.to_string(), val.clone());
            }
        }
        output::render(&Value::Object(head));
        let funding = items(v, "funding");
        if !funding.is_empty() {
            println!();
            output::table(&table_view(&funding, &["year", "deposits", "withdrawals"]));
        }
    });
    Ok(())
}

/// Map an `Account` node to the `account-summary/v1` DTO. Pure, so the
/// figure-selection (and the `hasValue`/omit logic) is contract-tested offline.
fn summary_dto(node: &Value) -> Result<Value, CliError> {
    let mut dto = json!({});
    if let Some(name) =
        parse::opt_string(node, "nickname").or_else(|| parse::opt_string(node, "name"))
    {
        dto["name"] = json!(name);
    }
    if let Some(reg) = parse::opt_string(node, "registration") {
        dto["registration"] = json!(reg);
    }
    let balance = node.get("balance").unwrap_or(&Value::Null);

    // Total value; a `hasValue: false` figure is one M1 itself couldn't price,
    // so it is omitted rather than shown as $0 (same rule as accounts list).
    if let Some(total) = balance.get("totalValue").and_then(|t| {
        if t.get("hasValue") == Some(&Value::Bool(false)) {
            return None;
        }
        parse::money_at(t, "value")
    }) {
        dto["total_value"] = serde_json::to_value(total).unwrap_or(Value::Null);
    }
    if let Some(cash) = balance
        .get("cash")
        .and_then(|c| parse::money_at(c, "available"))
    {
        dto["cash"] = serde_json::to_value(cash).unwrap_or(Value::Null);
    }

    let investments = balance.get("investments").unwrap_or(&Value::Null);
    if let Some(cost) = investments
        .get("totalCost")
        .and_then(|c| parse::money_at(c, "cost"))
    {
        dto["invested_cost"] = serde_json::to_value(cost).unwrap_or(Value::Null);
    }
    if let Some(mkt) = investments
        .get("totalValue")
        .and_then(|c| parse::money_at(c, "value"))
    {
        dto["market_value"] = serde_json::to_value(mkt).unwrap_or(Value::Null);
    }
    if let Some(g) = investments.get("totalUnrealizedGain") {
        if let Some(gain) = parse::money_at(g, "gain") {
            dto["unrealized_gain"] = serde_json::to_value(gain).unwrap_or(Value::Null);
        }
        if let Some(pct) = g.get("gainPercent").and_then(Value::as_f64) {
            dto["gain_percent"] = json!(pct);
        }
        // Surface M1's own "this gain is incomplete" flag (a value it couldn't
        // fully price), like `net-worth` does for its partial total — so a
        // consumer doesn't read a partial gain as final. Only when true.
        if g.get("isPartial") == Some(&Value::Bool(true)) {
            dto["gain_is_partial"] = json!(true);
        }
    }

    // The loud-failure guard fires whenever **no balance-derived figure** was
    // mapped — independent of `fundingTotals`, which is a separate GraphQL
    // field. Gating on funding-emptiness (as an earlier version did) would let
    // a dropped `balance` pass silently for any account that still has funding
    // history, exactly the silent-empty failure parse.rs forbids.
    const BALANCE_KEYS: [&str; 6] = [
        "total_value",
        "cash",
        "invested_cost",
        "market_value",
        "unrealized_gain",
        "gain_percent",
    ];
    if !BALANCE_KEYS.iter().any(|k| dto.get(*k).is_some()) {
        return Err(CliError::Upstream(
            "M1 returned no balance for this account — the summary shape may have changed".into(),
        ));
    }

    // Funding history: deposits vs withdrawals by year (lifetime, per year).
    let funding: Vec<Value> = node
        .get("fundingTotals")
        .and_then(|f| f.get("totalsByYear"))
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(funding_row).collect())
        .unwrap_or_default();
    dto["funding"] = json!(funding);

    Ok(dto)
}

fn funding_row(v: &Value) -> Option<Value> {
    let year = v.get("year").and_then(Value::as_i64)?;
    let mut row = json!({ "year": year });
    if let Some(dep) = parse::money_at(v, "totalDeposits") {
        row["deposits"] = serde_json::to_value(dep).ok()?;
    }
    if let Some(wd) = parse::money_at(v, "totalWithdrawals") {
        row["withdrawals"] = serde_json::to_value(wd).ok()?;
    }
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fabricated round dummies, never a real balance.
    fn node() -> Value {
        json!({
            "id": "acct-000000001",
            "name": "Individual Brokerage",
            "nickname": "Fun Money",
            "registration": "INDIVIDUAL",
            "balance": {
                "totalValue": { "value": 11500.07, "hasValue": true },
                "cash": { "available": 0.07 },
                "investments": {
                    "totalCost": { "cost": 10000.00 },
                    "totalValue": { "value": 11500.00 },
                    "totalUnrealizedGain": { "gain": 1500.00, "gainPercent": 15.0, "isPartial": false }
                }
            },
            "fundingTotals": {
                "totalsByYear": [
                    { "year": 2026, "totalDeposits": 10000.0, "totalWithdrawals": 0.0 }
                ]
            }
        })
    }

    #[test]
    fn summary_dto_rolls_up_performance_and_funding() {
        let dto = summary_dto(&node()).unwrap();
        assert_eq!(dto["name"], json!("Fun Money"));
        assert_eq!(dto["registration"], json!("INDIVIDUAL"));
        assert_eq!(dto["total_value"]["amount"], json!("11500.07"));
        assert_eq!(dto["cash"]["amount"], json!("0.07"));
        assert_eq!(dto["invested_cost"]["amount"], json!("10000.00"));
        assert_eq!(dto["market_value"]["amount"], json!("11500.00"));
        assert_eq!(dto["unrealized_gain"]["amount"], json!("1500.00"));
        assert_eq!(dto["gain_percent"], json!(15.0));
        let funding = dto["funding"].as_array().unwrap();
        assert_eq!(funding[0]["year"], json!(2026));
        assert_eq!(funding[0]["deposits"]["amount"], json!("10000.00"));
    }

    #[test]
    fn an_unpriced_total_is_omitted_not_zero() {
        let mut n = node();
        n["balance"]["totalValue"] = json!({ "value": 0.0, "hasValue": false });
        assert!(summary_dto(&n).unwrap().get("total_value").is_none());
    }

    #[test]
    fn an_account_with_no_balance_is_a_loud_error() {
        let n = json!({ "name": "x", "registration": "INDIVIDUAL", "fundingTotals": { "totalsByYear": [] } });
        assert_eq!(summary_dto(&n).unwrap_err().exit_code(), 5);
    }

    /// The guard must fire even when funding history is present — a dropped
    /// `balance` must not pass silently just because `fundingTotals` resolved.
    #[test]
    fn missing_balance_still_errors_when_funding_is_present() {
        let n = json!({
            "name": "x", "registration": "INDIVIDUAL",
            "fundingTotals": { "totalsByYear": [
                { "year": 2026, "totalDeposits": 100.0, "totalWithdrawals": 0.0 }
            ] }
        });
        assert_eq!(summary_dto(&n).unwrap_err().exit_code(), 5);
    }

    /// A gain M1 flags as incomplete must carry `gain_is_partial` so a consumer
    /// doesn't read it as final — mirroring net-worth's partial flag.
    #[test]
    fn a_partial_gain_is_flagged() {
        let mut n = node();
        n["balance"]["investments"]["totalUnrealizedGain"] =
            json!({ "gain": 100.0, "gainPercent": 1.0, "isPartial": true });
        let dto = summary_dto(&n).unwrap();
        assert_eq!(dto["gain_is_partial"], json!(true));
        // A complete gain carries no flag.
        assert!(summary_dto(&node())
            .unwrap()
            .get("gain_is_partial")
            .is_none());
    }

    #[test]
    fn a_negative_unrealized_gain_survives() {
        let mut n = node();
        n["balance"]["investments"]["totalUnrealizedGain"] =
            json!({ "gain": -12.5, "gainPercent": -0.4 });
        let dto = summary_dto(&n).unwrap();
        assert_eq!(dto["unrealized_gain"]["amount"], json!("-12.50"));
        assert_eq!(dto["gain_percent"], json!(-0.4));
    }
}
