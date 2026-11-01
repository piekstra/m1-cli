//! `m1f net-worth` — household net worth across every M1 product line, with
//! the Invest line broken out by account.
//!
//! The headline figures are M1's own home-screen rollup
//! (`viewer.overview.balances`): one net-worth total with an asset/liability
//! split and a per-product breakdown (Invest, Earn, Borrow, Spend). M1 gives
//! that breakdown by product only, so "Invest" lumps every investment
//! account together — a taxable brokerage, a Roth IRA and a rollover IRA in
//! one figure. A consumer that needs one account's balance (Form 8606 line 6
//! counts every traditional IRA and no Roth IRA) cannot read that.
//!
//! So the Invest row is replaced by one row per investment account, read
//! from `viewer.accounts` (`accounts::fetch_nodes`): its `account_id`,
//! `name`, family `type` (`accounts::family_type`: `ira_traditional`,
//! `ira_roth`, `individual`, …), `registration`, `is_retirement` and
//! `total`. The other product lines keep their own rows. The DTO's `total`,
//! `assets` and `liabilities` stay M1's figures, and the rows still sum to
//! what they summed to before: where the accounts' values do not add up to
//! M1's Invest figure to the cent, the difference is its own row
//! (`type: "Invest"`, named as unmatched) and a note goes to stderr — a
//! split never moves money in or out of the total. When an account M1 cannot
//! price is listed, that row is emitted even at 0.00, so "the unpriced
//! accounts hold nothing" reads apart from "no remainder was computed".

use pk_cli_core::{output, CliError, Money};
use serde_json::{json, Value};

use super::{accounts, emit, items, table_view, Ctx};
use crate::{graphql, parse};

/// M1's product line that holds the investment accounts.
const INVEST: &str = "Invest";

/// The name of the row carrying what the accounts do not account for.
const UNMATCHED_NAME: &str = "Invest (not matched to an account)";

/// The per-row columns of the human table, read from the same DTO `--json`
/// emits.
const TABLE_COLUMNS: &[&str] = &["product", "name", "type", "total"];

pub fn show(ctx: &Ctx) -> Result<(), CliError> {
    let data = ctx.read(|c| c.execute(graphql::NET_WORTH, json!({}), Some("NetWorthOverview")))?;
    let balances = parse::at(&data, &["viewer", "overview", "balances"])?;
    let account_nodes = accounts::fetch_nodes(ctx)?;
    let built = networth_dto(balances, &account_nodes)?;
    if let Some(diff) = &built.unmatched {
        if !ctx.common.quiet {
            eprintln!(
                "note: M1's Invest total and the sum of its accounts differ by {diff}; the \
                 difference is listed as its own `{INVEST}` row (\"{UNMATCHED_NAME}\")"
            );
        }
    }
    emit(ctx, "net-worth", built.dto, |v| {
        // Lead with the headline figures, then the per-account table.
        let mut head = serde_json::Map::new();
        for k in [
            "total",
            "assets",
            "liabilities",
            "asset_ratio",
            "is_partial",
        ] {
            if let Some(val) = v.get(k) {
                head.insert(k.to_string(), val.clone());
            }
        }
        output::render(&Value::Object(head));
        if v.get("accounts").is_some() {
            println!();
            output::table(&table_view(&items(v, "accounts"), TABLE_COLUMNS));
        }
    });
    Ok(())
}

/// The `net-worth/v1` DTO, and the Invest difference no account covers.
struct Built {
    dto: Value,
    /// Set when M1's Invest figure and the sum of its accounts differ.
    unmatched: Option<Money>,
}

/// Map `BalancesOverview` plus the login's account nodes to the
/// `net-worth/v1` DTO. Pure, so it is contract-tested offline like every
/// other read shape.
fn networth_dto(b: &Value, account_nodes: &[Value]) -> Result<Built, CliError> {
    let mut dto = json!({});
    if let Some(total) = parse::money_at(b, "total") {
        dto["total"] = serde_json::to_value(total).unwrap_or(Value::Null);
    }
    // `assets`/`liabilities` are `NetWorthLabel { label value }`; a null
    // `liabilities` (no debt) is omitted rather than rendered as $0.
    if let Some(assets) = b.get("assets").and_then(|a| parse::money_at(a, "value")) {
        dto["assets"] = serde_json::to_value(assets).unwrap_or(Value::Null);
    }
    if let Some(liabilities) = b
        .get("liabilities")
        .and_then(|l| parse::money_at(l, "value"))
    {
        dto["liabilities"] = serde_json::to_value(liabilities).unwrap_or(Value::Null);
    }
    if let Some(ratio) = b.get("assetRatio").and_then(Value::as_f64) {
        dto["asset_ratio"] = json!(ratio);
    }
    // Surface M1's own "this total is incomplete" flag so a machine consumer
    // doesn't treat a partial figure as final. Only present when true.
    if b.get("isPartialTotal") == Some(&Value::Bool(true)) {
        dto["is_partial"] = json!(true);
    }
    let mut rows: Vec<Value> = Vec::new();
    let mut unmatched = None;
    for t in parse::nodes(b, &["accountTotals"]).unwrap_or_default() {
        let (Some(kind), Some(total)) =
            (parse::opt_string(&t, "type"), parse::money_at(&t, "total"))
        else {
            continue;
        };
        if kind == INVEST {
            let split = invest_rows(&total, account_nodes)?;
            rows.extend(split.rows);
            unmatched = split.unmatched;
        } else {
            rows.push(product_row(&kind, &kind, None, total));
        }
    }
    if !rows.is_empty() {
        dto["accounts"] = json!(rows);
    }
    if dto.as_object().is_some_and(|m| m.is_empty()) {
        return Err(CliError::Upstream(
            "M1 returned an empty net-worth object — the overview shape may have changed".into(),
        ));
    }
    Ok(Built { dto, unmatched })
}

/// A product-line row: `type` is M1's product name (`Earn`, `Borrow`, …),
/// so a consumer that reads product lines keeps reading them.
fn product_row(kind: &str, product: &str, name: Option<&str>, total: Money) -> Value {
    let mut row = json!({ "type": kind, "product": product });
    if let Some(name) = name {
        row["name"] = json!(name);
    }
    row["total"] = serde_json::to_value(total).unwrap_or(Value::Null);
    row
}

/// The Invest line, one row per account, plus the remainder row when the
/// accounts do not sum to it or one of them has no `total`.
struct InvestSplit {
    rows: Vec<Value>,
    unmatched: Option<Money>,
}

/// One row per investment account in place of M1's Invest figure.
///
/// A closed or rejected account that holds nothing is left out (it is
/// history, not net worth); every other account appears, and one M1 cannot
/// price (`hasValue: false`) appears without a `total` — its value is then
/// in the remainder row rather than shown as $0.00. With such a row listed,
/// the remainder row is emitted even when it is exactly 0.00: it is the only
/// figure that bounds what the unpriced accounts hold. With every account
/// priced, it is emitted only when non-zero. An account node without the
/// `isRetirement` flag fails the read, as every household read does
/// (`AccountRef::from_node`).
fn invest_rows(invest: &Money, nodes: &[Value]) -> Result<InvestSplit, CliError> {
    let invest_cents = parse::cents(&invest.amount).ok_or_else(|| {
        CliError::Upstream(format!(
            "M1's Invest total `{}` does not read as a decimal amount",
            invest.amount
        ))
    })?;
    let mut rows = Vec::new();
    let mut matched: i64 = 0;
    let mut any_unpriced = false;
    for node in nodes {
        let acct = accounts::AccountRef::from_node(node)?;
        let total = accounts::total_value(node);
        let cents = match &total {
            Some(m) => Some(parse::cents(&m.amount).ok_or_else(|| {
                CliError::Upstream(format!(
                    "account `{}` has a total `{}` that does not read as a decimal amount",
                    acct.id, m.amount
                ))
            })?),
            None => None,
        };
        let closed = matches!(
            parse::opt_string(node, "status").as_deref(),
            Some("CLOSED" | "REJECTED")
        );
        if closed && cents.unwrap_or(0) == 0 {
            continue;
        }
        matched += cents.unwrap_or(0);
        let mut row = json!({ "account_id": acct.id });
        if let Some(name) = &acct.name {
            row["name"] = json!(name);
        }
        if let Some(kind) = acct.account_type() {
            row["type"] = json!(kind);
        }
        if let Some(reg) = &acct.registration {
            row["registration"] = json!(reg);
        }
        row["is_retirement"] = json!(acct.is_retirement);
        row["product"] = json!(INVEST);
        match total {
            Some(total) => row["total"] = serde_json::to_value(total).unwrap_or(Value::Null),
            None => any_unpriced = true,
        }
        rows.push(row);
    }
    let diff = invest_cents - matched;
    let unmatched = (diff != 0).then(|| Money::from_cents(diff));
    if diff != 0 || any_unpriced {
        rows.push(product_row(
            INVEST,
            INVEST,
            Some(UNMATCHED_NAME),
            Money::from_cents(diff),
        ));
    }
    Ok(InvestSplit { rows, unmatched })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fabricated round-ish dummies, never a real balance.
    fn balances() -> Value {
        json!({
            "total": 12345.67,
            "assetRatio": 1.0,
            "isPartialTotal": false,
            "assets": { "label": "Assets", "value": 12345.67 },
            "liabilities": null,
            "accountTotals": [
                { "type": "Invest", "total": 12000.00 },
                { "type": "Earn", "total": 345.67 }
            ]
        })
    }

    fn account(id: &str, name: &str, reg: &str, value: Value, has_value: bool) -> Value {
        json!({
            "id": id,
            "name": name,
            "nickname": null,
            "registration": reg,
            "isRetirement": reg.ends_with("_IRA"),
            "status": "OPENED",
            "balance": { "totalValue": { "value": value, "hasValue": has_value } }
        })
    }

    /// Three accounts summing exactly to the Invest figure.
    fn accounts_matching() -> Vec<Value> {
        vec![
            account(
                "acct-000000001",
                "Taxable",
                "INDIVIDUAL",
                json!(2000.0),
                true,
            ),
            account(
                "acct-000000002",
                "Roth IRA",
                "ROTH_IRA",
                json!(1500.5),
                true,
            ),
            account(
                "acct-000000003",
                "Rollover",
                "TRADITIONAL_IRA",
                json!(8499.5),
                true,
            ),
        ]
    }

    fn row_cents(dto: &Value) -> i64 {
        dto["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|r| r["total"]["amount"].as_str())
            .map(|a| parse::cents(a).unwrap())
            .sum()
    }

    #[test]
    fn the_headline_figures_stay_m1s_own() {
        let built = networth_dto(&balances(), &accounts_matching()).unwrap();
        let dto = &built.dto;
        assert_eq!(dto["total"]["amount"], json!("12345.67"));
        assert_eq!(dto["assets"]["amount"], json!("12345.67"));
        // No debt → liabilities omitted, not $0.
        assert!(dto.get("liabilities").is_none());
        assert_eq!(dto["asset_ratio"], json!(1.0));
        // is_partial only present when true.
        assert!(dto.get("is_partial").is_none());
    }

    #[test]
    fn the_invest_line_is_one_row_per_account_with_its_family_type() {
        let built = networth_dto(&balances(), &accounts_matching()).unwrap();
        assert!(built.unmatched.is_none());
        let rows = built.dto["accounts"].as_array().unwrap().clone();
        assert_eq!(rows.len(), 4, "three accounts + Earn: {rows:?}");
        let types: Vec<&str> = rows.iter().map(|r| r["type"].as_str().unwrap()).collect();
        assert_eq!(types, ["individual", "ira_roth", "ira_traditional", "Earn"]);
        let rollover = &rows[2];
        assert_eq!(rollover["account_id"], json!("acct-000000003"));
        assert_eq!(rollover["name"], json!("Rollover"));
        assert_eq!(rollover["registration"], json!("TRADITIONAL_IRA"));
        assert_eq!(rollover["is_retirement"], json!(true));
        assert_eq!(rollover["product"], json!("Invest"));
        assert_eq!(rollover["total"]["amount"], json!("8499.50"));
        // No lumped Invest row remains when the accounts cover it.
        assert!(rows.iter().all(|r| r["type"] != "Invest"));
        // Product lines keep their M1 name, and say which product they are.
        assert_eq!(rows[3]["product"], json!("Earn"));
    }

    #[test]
    fn the_rows_sum_to_what_the_product_lines_summed_to() {
        let built = networth_dto(&balances(), &accounts_matching()).unwrap();
        // 12000.00 Invest + 345.67 Earn.
        assert_eq!(row_cents(&built.dto), 1_234_567);
    }

    #[test]
    fn a_shortfall_becomes_an_unmatched_invest_row_and_totals_stay_equal() {
        let mut accts = accounts_matching();
        accts.pop(); // the 8499.50 rollover is not on the list
        let built = networth_dto(&balances(), &accts).unwrap();
        assert_eq!(built.unmatched.as_ref().unwrap().amount, "8499.50");
        let rows = built.dto["accounts"].as_array().unwrap();
        let rest = rows.iter().find(|r| r["name"] == UNMATCHED_NAME).unwrap();
        assert_eq!(rest["type"], json!("Invest"));
        assert_eq!(rest["total"]["amount"], json!("8499.50"));
        assert_eq!(row_cents(&built.dto), 1_234_567);
    }

    #[test]
    fn an_overshoot_is_a_negative_unmatched_row_so_totals_stay_equal() {
        let mut accts = accounts_matching();
        accts.push(account(
            "acct-000000004",
            "Extra",
            "JOINT",
            json!(0.25),
            true,
        ));
        let built = networth_dto(&balances(), &accts).unwrap();
        assert_eq!(built.unmatched.as_ref().unwrap().amount, "-0.25");
        assert_eq!(row_cents(&built.dto), 1_234_567);
    }

    /// The remainder row's whole shape: M1's product name as `type`, no
    /// `account_id`, the unmatched name, and the amount.
    fn remainder_row(amount: &str) -> Value {
        json!({
            "type": "Invest",
            "product": "Invest",
            "name": UNMATCHED_NAME,
            "total": { "amount": amount, "currency": "USD" }
        })
    }

    fn remainder_rows(dto: &Value) -> Vec<Value> {
        dto["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["type"] == INVEST && r.get("account_id").is_none())
            .cloned()
            .collect()
    }

    /// M1's Invest figure lowered to what the taxable and rollover accounts
    /// hold (2000.00 + 8499.50), so with the Roth IRA unpriced the remainder
    /// is exactly 0.00.
    fn balances_without_the_roth() -> Value {
        let mut b = balances();
        b["accountTotals"][0]["total"] = json!(10499.50);
        b
    }

    fn accounts_with_the_roth_unpriced() -> Vec<Value> {
        let mut accts = accounts_matching();
        accts[1] = account("acct-000000002", "Roth IRA", "ROTH_IRA", json!(0), false);
        accts
    }

    #[test]
    fn an_unpriced_account_is_listed_without_a_total_and_its_value_stays_in_the_remainder() {
        let built = networth_dto(&balances(), &accounts_with_the_roth_unpriced()).unwrap();
        let rows = built.dto["accounts"].as_array().unwrap();
        let roth = rows.iter().find(|r| r["type"] == "ira_roth").unwrap();
        assert!(roth.get("total").is_none(), "never a fake $0: {roth}");
        assert_eq!(built.unmatched.as_ref().unwrap().amount, "1500.50");
        assert_eq!(remainder_rows(&built.dto), [remainder_row("1500.50")]);
        assert_eq!(row_cents(&built.dto), 1_234_567);
    }

    #[test]
    fn an_unpriced_account_with_an_exact_remainder_still_emits_the_row_at_zero() {
        let built = networth_dto(
            &balances_without_the_roth(),
            &accounts_with_the_roth_unpriced(),
        )
        .unwrap();
        assert_eq!(remainder_rows(&built.dto), [remainder_row("0.00")]);
        // Nothing differs, so there is no stderr note.
        assert!(built.unmatched.is_none());
        // The row follows the accounts, before the next product line.
        let rows = built.dto["accounts"].as_array().unwrap();
        assert_eq!(rows[3], remainder_row("0.00"));
        assert_eq!(rows[4]["type"], json!("Earn"));
        // 10499.50 Invest + 345.67 Earn.
        assert_eq!(row_cents(&built.dto), 1_084_517);
    }

    #[test]
    fn the_human_table_lists_the_zero_remainder_row_too() {
        let built = networth_dto(
            &balances_without_the_roth(),
            &accounts_with_the_roth_unpriced(),
        )
        .unwrap();
        let table = table_view(&items(&built.dto, "accounts"), TABLE_COLUMNS);
        assert_eq!(table.len(), built.dto["accounts"].as_array().unwrap().len());
        assert!(
            table.contains(&remainder_row("0.00")),
            "the table carries every column of the row: {table:?}"
        );
    }

    #[test]
    fn every_account_priced_and_exact_emits_no_remainder_row() {
        let built = networth_dto(&balances(), &accounts_matching()).unwrap();
        assert!(remainder_rows(&built.dto).is_empty(), "{}", built.dto);
        assert!(built.unmatched.is_none());
    }

    #[test]
    fn a_priced_zero_balance_account_is_not_unpriced() {
        let mut accts = accounts_matching();
        accts.push(account(
            "acct-000000005",
            "Empty",
            "TRADITIONAL_IRA",
            json!(0.0),
            true,
        ));
        let built = networth_dto(&balances(), &accts).unwrap();
        let empty = &built.dto["accounts"][3];
        assert_eq!(empty["total"]["amount"], json!("0.00"));
        assert!(remainder_rows(&built.dto).is_empty(), "{}", built.dto);
    }

    #[test]
    fn an_unpriced_account_left_out_as_closed_does_not_force_the_row() {
        let mut accts = accounts_matching();
        let mut closed = account("acct-000000009", "Old", "ROTH_IRA", json!(0), false);
        closed["status"] = json!("CLOSED");
        accts.push(closed);
        let built = networth_dto(&balances(), &accts).unwrap();
        let rows = built.dto["accounts"].as_array().unwrap();
        assert!(rows.iter().all(|r| r["account_id"] != "acct-000000009"));
        assert!(remainder_rows(&built.dto).is_empty(), "{}", built.dto);
    }

    #[test]
    fn a_closed_empty_account_is_left_out() {
        let mut accts = accounts_matching();
        let mut closed = account("acct-000000009", "Old", "INDIVIDUAL", json!(0.0), true);
        closed["status"] = json!("CLOSED");
        accts.push(closed);
        let built = networth_dto(&balances(), &accts).unwrap();
        let rows = built.dto["accounts"].as_array().unwrap();
        assert!(rows.iter().all(|r| r["account_id"] != "acct-000000009"));
    }

    #[test]
    fn an_unknown_registration_keeps_its_row_without_a_type() {
        let mut accts = accounts_matching();
        accts[0]["registration"] = json!("SOMETHING_NEW");
        let built = networth_dto(&balances(), &accts).unwrap();
        let row = &built.dto["accounts"][0];
        assert!(row.get("type").is_none(), "{row}");
        assert_eq!(row["registration"], json!("SOMETHING_NEW"));
    }

    #[test]
    fn without_accounts_the_invest_line_is_one_unmatched_row() {
        let built = networth_dto(&balances(), &[]).unwrap();
        let rows = built.dto["accounts"].as_array().unwrap();
        assert_eq!(rows[0]["type"], json!("Invest"));
        assert_eq!(rows[0]["total"]["amount"], json!("12000.00"));
        assert_eq!(row_cents(&built.dto), 1_234_567);
    }

    #[test]
    fn an_account_without_the_retirement_flag_fails_the_read() {
        let mut accts = accounts_matching();
        accts[0].as_object_mut().unwrap().remove("isRetirement");
        let err = networth_dto(&balances(), &accts).err().unwrap();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn a_partial_total_is_flagged() {
        let mut b = balances();
        b["isPartialTotal"] = json!(true);
        assert_eq!(
            networth_dto(&b, &accounts_matching()).unwrap().dto["is_partial"],
            json!(true)
        );
    }

    #[test]
    fn liabilities_render_when_present() {
        let mut b = balances();
        b["liabilities"] = json!({ "label": "Liabilities", "value": 1500.0 });
        assert_eq!(
            networth_dto(&b, &accounts_matching()).unwrap().dto["liabilities"]["amount"],
            json!("1500.00")
        );
    }

    #[test]
    fn an_empty_object_is_a_loud_error() {
        assert_eq!(networth_dto(&json!({}), &[]).err().unwrap().exit_code(), 5);
    }
}
