//! `m1f holdings list` — positions held in one account.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{accounts, emit, items, note_empty, paginate, table_view, Ctx};
use crate::{graphql, parse};

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;

    let rows = collect(
        ctx.selected_account(),
        || accounts::scope(ctx, None),
        |account| fetch_nodes(ctx, account),
    )?;
    let rows = paginate(rows, "date", range);

    if rows.is_empty() {
        note_empty(ctx, "holdings");
    }
    emit(ctx, "holding-list", json!({ "items": rows }), |v| {
        output::table(&table_view(
            &items(v, "items"),
            &[
                "symbol",
                "name",
                "quantity",
                "value",
                "cost_basis",
                "dividend_yield",
                "account_name",
            ],
        ));
    });
    Ok(())
}

/// The holdings rows for a selection.
///
/// A selected account (flag, env, or config — see `Ctx::selected_account`)
/// reads that one account, unstamped, as before. With nothing selected the
/// read spans every account on the login and stamps each row with its
/// account: live on 2026-09-23 the bare `holdings list` was a usage error,
/// which is what blocked a household positions capture. Split from `list`
/// so both branches are testable offline.
fn collect(
    selected: Option<String>,
    scope: impl FnOnce() -> Result<Vec<accounts::AccountRef>, CliError>,
    mut fetch: impl FnMut(&str) -> Result<Vec<Value>, CliError>,
) -> Result<Vec<Value>, CliError> {
    match selected {
        Some(account) => fetch(&account)?.iter().map(holding_dto).collect(),
        None => accounts::rows_across(&scope()?, |acct| {
            fetch(&acct.id)?.iter().map(holding_dto).collect()
        }),
    }
}

/// Every position node in one account, following cursors (capped).
pub fn fetch_nodes(ctx: &Ctx, account: &str) -> Result<Vec<Value>, CliError> {
    // Positions hang off `balance.investments`, not off the account itself
    // (schema-verified).
    const PATH: &[&str] = &["node", "balance", "investments", "positions"];
    const MAX_PAGES: usize = 20;
    let mut cursor: Option<String> = None;
    let mut out: Vec<Value> = Vec::new();
    let mut pages = 0usize;
    loop {
        let vars = json!({ "accountId": account, "first": 100, "after": cursor });
        let data = ctx.read(|c| {
            c.execute(
                graphql::HOLDINGS,
                vars.clone(),
                Some("InvestmentsTablePagination"),
            )
        })?;
        parse::require_node(&data)?;
        let container = parse::at(&data, PATH)?.clone();
        out.extend(parse::nodes(&data, PATH)?);
        pages += 1;
        let next = parse::next_cursor(&container);
        if next.is_none() || next == cursor || pages >= MAX_PAGES {
            break;
        }
        cursor = next;
    }
    Ok(out)
}

pub fn holding_dto(v: &Value) -> Result<Value, CliError> {
    let security = v.get("security").unwrap_or(v);
    let symbol = parse::opt_string(security, "symbol")
        .or_else(|| parse::opt_string(v, "symbol"))
        .or_else(|| parse::opt_string(v, "ticker"));

    // Lead with the symbol when we have one — it is what a human identifies a
    // position by — but never fail for want of it; an id is enough.
    let mut dto = json!({});
    if let Some(sym) = &symbol {
        dto["symbol"] = json!(sym);
    }
    dto["id"] = json!(parse::id(v, "id")?);
    if let Some(name) = parse::opt_string(security, "name").or_else(|| parse::opt_string(v, "name"))
    {
        dto["name"] = json!(name);
    }
    // Quantity is a share count, not money: keep it a plain string decimal so
    // it never renders with a currency symbol (and fractional slices survive).
    if let Some(q) = parse::decimal_string(v, "quantity") {
        dto["quantity"] = json!(q);
    }
    // `value` and `cost` are nested objects (schema-verified):
    // `value { value priceDate }`, `cost { cost averageSharePrice }`. The flat
    // fallbacks keep older fixture shapes and gateway inlining working.
    let value_obj = v.get("value").filter(|x| x.is_object());
    if let Some(val) = value_obj
        .and_then(|x| parse::money_at(x, "value"))
        .or_else(|| parse::money_at(v, "value"))
    {
        dto["value"] = serde_json::to_value(val).unwrap_or(Value::Null);
    }
    let cost_obj = v.get("cost").filter(|x| x.is_object());
    if let Some(cb) = cost_obj
        .and_then(|x| parse::money_at(x, "cost"))
        .or_else(|| parse::money_at(v, "costBasis"))
    {
        dto["cost_basis"] = serde_json::to_value(cb).unwrap_or(Value::Null);
    }
    if let Some(avg) = cost_obj.and_then(|x| parse::money_at(x, "averageSharePrice")) {
        dto["avg_price"] = serde_json::to_value(avg).unwrap_or(Value::Null);
    }
    if let Some(gain) = v
        .get("unrealizedGain")
        .and_then(|g| parse::money_at(g, "gain"))
    {
        dto["unrealized_gain"] = serde_json::to_value(gain).unwrap_or(Value::Null);
    }
    // Dividend detail (schema-verified): `dividendYield`/`yieldOnCost` are
    // percentages (`Float`), `dividendFrequency` an enum. `lastTwelveMonthsPaid`
    // is a pre-formatted display string M1 renders as "$--" when it has no
    // figure, so that placeholder is dropped rather than shown.
    if let Some(div) = v.get("dividends").filter(|d| d.is_object()) {
        if let Some(y) = div.get("dividendYield").and_then(Value::as_f64) {
            dto["dividend_yield"] = json!(y);
        }
        if let Some(y) = div.get("yieldOnCost").and_then(Value::as_f64) {
            dto["yield_on_cost"] = json!(y);
        }
        if let Some(freq) = parse::opt_string(div, "dividendFrequency") {
            dto["dividend_frequency"] = json!(freq);
        }
        if let Some(ltm) = parse::opt_string(div, "lastTwelveMonthsPaid")
            .filter(|s| s.chars().any(|c| c.is_ascii_digit()))
        {
            dto["dividends_ltm"] = json!(ltm);
        }
    }
    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(id: &str, symbol: &str) -> Value {
        json!({ "id": id, "security": { "symbol": symbol } })
    }

    fn two_accounts() -> Vec<accounts::AccountRef> {
        ["acct-a", "acct-b"]
            .iter()
            .map(|id| accounts::AccountRef {
                id: (*id).into(),
                name: None,
                registration: Some("INDIVIDUAL".into()),
                is_retirement: false,
            })
            .collect()
    }

    #[test]
    fn a_selected_account_reads_only_that_account_unstamped() {
        let mut asked = Vec::new();
        let rows = collect(
            Some("acct-a".into()),
            || panic!("a selected account must not enumerate the login"),
            |a| {
                asked.push(a.to_string());
                Ok(vec![node("h1", "VTI")])
            },
        )
        .unwrap();
        assert_eq!(asked, ["acct-a"]);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].get("account_id").is_none());
    }

    #[test]
    fn nothing_selected_spans_every_account_and_stamps_rows() {
        let rows = collect(
            None,
            || Ok(two_accounts()),
            |a| Ok(vec![node(&format!("h-{a}"), "VTI")]),
        )
        .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["account_id"], json!("acct-a"));
        assert_eq!(rows[1]["account_id"], json!("acct-b"));
        assert_eq!(rows[1]["registration"], json!("INDIVIDUAL"));
    }

    #[test]
    fn holding_dto_reads_the_nested_security() {
        // The real schema shape: cost/value/unrealizedGain are wrapper objects.
        let v = json!({
            "id": "h1", "quantity": 2.5,
            "value": { "value": 300.0, "priceDate": "2026-08-13" },
            "cost": { "cost": 250.0, "averageSharePrice": 100.0 },
            "unrealizedGain": { "gain": 50.0, "gainPercent": 20.0 },
            "security": { "symbol": "VOO", "name": "Vanguard S&P 500 ETF" }
        });
        let dto = holding_dto(&v).unwrap();
        assert_eq!(dto["symbol"], json!("VOO"));
        assert_eq!(dto["name"], json!("Vanguard S&P 500 ETF"));
        assert_eq!(dto["value"]["amount"], json!("300.00"));
        assert_eq!(dto["cost_basis"]["amount"], json!("250.00"));
        assert_eq!(dto["avg_price"]["amount"], json!("100.00"));
        assert_eq!(dto["unrealized_gain"]["amount"], json!("50.00"));
    }

    #[test]
    fn holding_dto_maps_dividend_detail() {
        let v = json!({
            "id": "h1",
            "dividends": {
                "dividendYield": 1.07,
                "yieldOnCost": 1.09,
                "dividendFrequency": "QUARTERLY",
                "lastTwelveMonthsPaid": "$13.20"
            },
            "security": { "symbol": "VTI" }
        });
        let dto = holding_dto(&v).unwrap();
        assert_eq!(dto["dividend_yield"], json!(1.07));
        assert_eq!(dto["yield_on_cost"], json!(1.09));
        assert_eq!(dto["dividend_frequency"], json!("QUARTERLY"));
        assert_eq!(dto["dividends_ltm"], json!("$13.20"));
    }

    #[test]
    fn the_dollar_dash_placeholder_ltm_is_dropped() {
        // M1 renders "$--" when it has no LTM figure; that must not surface.
        let v = json!({
            "id": "h1",
            "dividends": { "dividendYield": 0.4, "lastTwelveMonthsPaid": "$--" },
            "security": { "symbol": "VUG" }
        });
        let dto = holding_dto(&v).unwrap();
        assert_eq!(dto["dividend_yield"], json!(0.4));
        assert!(dto.get("dividends_ltm").is_none(), "placeholder leaked");
    }

    #[test]
    fn a_position_without_dividends_omits_the_fields() {
        let dto = holding_dto(&json!({ "id": "h1", "security": { "symbol": "X" } })).unwrap();
        assert!(dto.get("dividend_yield").is_none());
    }

    #[test]
    fn flat_value_and_cost_basis_still_parse() {
        let v = json!({ "id": "h1", "value": 300.0, "costBasis": 250.0 });
        let dto = holding_dto(&v).unwrap();
        assert_eq!(dto["value"]["amount"], json!("300.00"));
        assert_eq!(dto["cost_basis"]["amount"], json!("250.00"));
    }

    #[test]
    fn fractional_shares_are_not_rounded() {
        let dto = holding_dto(&json!({ "id": "h", "quantity": 0.12345 })).unwrap();
        assert_eq!(dto["quantity"], json!("0.12345"));
    }

    #[test]
    fn a_flat_shape_without_a_security_object_still_works() {
        let v = json!({ "id": "h2", "symbol": "AAPL", "quantity": "1" });
        let dto = holding_dto(&v).unwrap();
        assert_eq!(dto["symbol"], json!("AAPL"));
        assert_eq!(dto["quantity"], json!("1"));
    }

    #[test]
    fn a_missing_id_fails_loudly() {
        assert_eq!(
            holding_dto(&json!({ "symbol": "X" }))
                .unwrap_err()
                .exit_code(),
            5
        );
    }
}
