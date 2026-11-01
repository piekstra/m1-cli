//! `m1f ira` — IRA contribution tracking: how much room is left this year.
//!
//! Reads `Account.iraContributionTotals` / `iraContributionLimits` for the
//! selected account. Tax-relevant: for each year it shows the contribution
//! made, the IRS max, and the remaining room — the number you check before the
//! April deadline. Contribution fields exist on every account, but only an IRA
//! returns meaningful figures, so a non-IRA account is reported as such.

use pk_cli_core::{output, CliError, Money};
use serde_json::{json, Value};

use super::{emit, items, table_view, Ctx};
use crate::{graphql, parse};

pub fn show(ctx: &Ctx) -> Result<(), CliError> {
    let account = ctx.account()?;
    let data = ctx.read(|c| {
        c.execute(
            graphql::IRA_CONTRIBUTIONS,
            json!({ "accountId": account }),
            Some("IraContributions"),
        )
    })?;
    parse::require_node(&data)?;
    let node = parse::at(&data, &["node"])?;
    let dto = ira_dto(node)?;

    if dto["years"].as_array().is_some_and(|y| y.is_empty()) && !ctx.common.quiet {
        let reg = dto
            .get("registration")
            .and_then(Value::as_str)
            .unwrap_or("");
        if reg.contains("IRA") {
            eprintln!("no IRA contribution history for this account");
        } else {
            eprintln!("this account ({reg}) is not an IRA — no contribution limits apply");
        }
    }

    emit(ctx, "ira-contributions", dto, |v| {
        let mut head = serde_json::Map::new();
        for k in ["registration", "current_year_limit"] {
            if let Some(val) = v.get(k) {
                head.insert(k.to_string(), val.clone());
            }
        }
        output::render(&Value::Object(head));
        // Emptiness, not key presence: `ira_dto` always sets `years` (to `[]`
        // for a non-IRA account), so gating on `is_some()` would print a bare
        // table header for an account that has no contribution rows. Mirrors
        // the `rows.is_empty()` guard in holdings.rs / lots.rs.
        let years = items(v, "years");
        if !years.is_empty() {
            println!();
            output::table(&table_view(
                &years,
                &["year", "contributed", "max", "remaining"],
            ));
        }
    });
    Ok(())
}

/// Map an `Account` node to the `ira-contributions/v1` DTO. Pure, so the
/// remaining-room math is contract-tested offline.
fn ira_dto(node: &Value) -> Result<Value, CliError> {
    let mut dto = json!({});
    if let Some(reg) = parse::opt_string(node, "registration") {
        dto["registration"] = json!(reg);
    }
    if let Some(limit) = node
        .get("iraContributionLimits")
        .and_then(|l| parse::money_at(l, "currentYearLimit"))
    {
        dto["current_year_limit"] = serde_json::to_value(limit).unwrap_or(Value::Null);
    }
    let years: Vec<Value> = node
        .get("iraContributionTotals")
        .and_then(|t| t.get("totalsByYear"))
        .and_then(Value::as_array)
        .map(|rows| rows.iter().filter_map(year_row).collect())
        .unwrap_or_default();
    dto["years"] = json!(years);
    Ok(dto)
}

/// One `{ year, contributed, max, remaining }` row. `remaining` is computed in
/// integer cents (never float money math) and clamped at zero — you can't have
/// negative room.
fn year_row(v: &Value) -> Option<Value> {
    let year = v.get("year").and_then(Value::as_i64)?;
    let contributed = parse::money_at(v, "totalContribution");
    let max = parse::money_at(v, "maxContribution");
    let mut row = json!({ "year": year });
    if let Some(c) = &contributed {
        row["contributed"] = serde_json::to_value(c.clone()).ok()?;
    }
    if let Some(m) = &max {
        row["max"] = serde_json::to_value(m.clone()).ok()?;
    }
    if let (Some(c), Some(m)) = (&contributed, &max) {
        if let Some(rem) = remaining(c, m) {
            row["remaining"] = serde_json::to_value(rem).ok()?;
        }
    }
    Some(row)
}

/// `max - contributed`, in integer cents, clamped at zero. Returns None if
/// either value doesn't parse as a decimal (rather than guessing).
fn remaining(contributed: &Money, max: &Money) -> Option<Money> {
    let rem = (parse::cents(&max.amount)? - parse::cents(&contributed.amount)?).max(0);
    Some(Money::from_cents(rem))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roth_node() -> Value {
        json!({
            "id": "acct-000000002",
            "registration": "ROTH_IRA",
            "iraContributionLimits": { "currentYearLimit": 7500 },
            "iraContributionTotals": {
                "totalsByYear": [
                    { "year": 2026, "totalContribution": 2000.0, "maxContribution": 7500.0 },
                    { "year": 2025, "totalContribution": 7000.0, "maxContribution": 7000.0 }
                ]
            }
        })
    }

    #[test]
    fn ira_dto_computes_remaining_room() {
        let dto = ira_dto(&roth_node()).unwrap();
        assert_eq!(dto["registration"], json!("ROTH_IRA"));
        assert_eq!(dto["current_year_limit"]["amount"], json!("7500.00"));
        let years = dto["years"].as_array().unwrap();
        assert_eq!(years.len(), 2);
        // 7500 - 2000 = 5500 room left in 2026.
        assert_eq!(years[0]["year"], json!(2026));
        assert_eq!(years[0]["contributed"]["amount"], json!("2000.00"));
        assert_eq!(years[0]["remaining"]["amount"], json!("5500.00"));
        // Maxed out in 2025 → zero remaining, not negative.
        assert_eq!(years[1]["remaining"]["amount"], json!("0.00"));
    }

    #[test]
    fn remaining_is_clamped_at_zero_when_overcontributed() {
        // Defensive: an excess contribution must not show negative room.
        let rem = remaining(
            &Money::usd("8000.00".to_string()),
            &Money::usd("7500.00".to_string()),
        )
        .unwrap();
        assert_eq!(rem.amount, "0.00");
    }

    #[test]
    fn remaining_handles_fractional_dollars_exactly() {
        let rem = remaining(
            &Money::usd("1234.56".to_string()),
            &Money::usd("7000.00".to_string()),
        )
        .unwrap();
        assert_eq!(rem.amount, "5765.44");
    }

    #[test]
    fn a_non_ira_account_yields_no_year_rows() {
        let node = json!({
            "registration": "INDIVIDUAL",
            "iraContributionTotals": { "totalsByYear": [] }
        });
        let dto = ira_dto(&node).unwrap();
        assert_eq!(dto["registration"], json!("INDIVIDUAL"));
        assert!(dto["years"].as_array().unwrap().is_empty());
    }
}
