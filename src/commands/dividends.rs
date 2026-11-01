//! `m1f dividends list` — dividend payments across the household's accounts,
//! in the family's `dividend-list/v1` shape (the one `rhd` and `alp` answer).
//!
//! The read is typed, not keyword-matched: the activity feed's server-side
//! `includeCategoryDividend` filter returns dividend entries only (observed
//! live 2026-09-23 — see `graphql::DIVIDENDS`). Every row carries its account
//! facts (`account_id`, `account_name`, `registration`, `is_retirement`),
//! because a dividend paid inside an IRA is not taxable income and a consumer
//! summing 1099-DIV figures has to be able to leave it out. That decision is
//! the consumer's; this command reports every account's dividends.
//!
//! Like `positions list`, it spans every account unless `--account` /
//! `M1F_ACCOUNT` names one; the config default account is not consulted.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{accounts, emit, items, note_empty, table_view, Ctx};
use crate::{graphql, parse};

/// Ceiling on cursor pages per account, as in `activity list`: a cursor that
/// never advances must not spin forever against a rate-limited API. Hitting
/// it is reported in the DTO, never silently truncated.
const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;
const PATH: &[&str] = &["node", "investActivity", "activity"];

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;
    let filter = filter_for(range);

    let mut truncated = false;
    let accts = accounts::scope(ctx, ctx.household_selection())?;
    let rows = accounts::rows_across(&accts, |acct| {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let vars = json!({
                "accountId": acct.id,
                "first": PAGE_SIZE,
                "after": cursor,
                "filter": filter,
            });
            let data =
                ctx.read(|c| c.execute(graphql::DIVIDENDS, vars.clone(), Some("InvestDividends")))?;
            parse::require_node(&data)?;
            let container = parse::at(&data, PATH)?.clone();
            for node in parse::nodes(&data, PATH)? {
                out.push(dividend_row(&node)?);
            }
            pages += 1;
            let next = parse::next_cursor(&container);
            if next.is_none() || next == cursor {
                break;
            }
            if pages >= MAX_PAGES {
                truncated = true;
                break;
            }
            cursor = next;
        }
        Ok(out)
    })?;
    if truncated && !ctx.common.quiet {
        eprintln!(
            "stopped after {MAX_PAGES} pages in an account — narrow the window with \
             --since/--until"
        );
    }

    let rows = finish(rows, range);
    if rows.is_empty() {
        note_empty(ctx, "dividends");
    }
    emit(
        ctx,
        "dividend-list",
        json!({ "items": rows, "truncated": truncated }),
        |v| {
            output::table(&table_view(
                &items(v, "items"),
                &["date", "symbol", "amount", "account_name", "registration"],
            ));
        },
    );
    Ok(())
}

/// The server-side filter: dividends only, bounded by the range when given.
/// Both bounds are inclusive server-side (observed live).
fn filter_for(range: &RangeArgs) -> Value {
    let mut f = json!({ "includeCategoryDividend": true });
    if let Some(since) = &range.since {
        f["fromDate"] = json!(since);
    }
    if let Some(until) = &range.until {
        f["toDate"] = json!(until);
    }
    f
}

/// Merge the per-account rows newest first, re-apply the window client-side
/// (the server bounds it too; this keeps the contract independent of that),
/// then cap at `--limit`.
fn finish(mut rows: Vec<Value>, range: &RangeArgs) -> Vec<Value> {
    rows.sort_by(|a, b| {
        let d = |r: &Value| r.get("date").and_then(Value::as_str).map(str::to_string);
        d(b).cmp(&d(a))
    });
    super::paginate(rows, "date", range)
}

/// One dividend row.
///
/// Fails loudly on anything the filter should not have returned — a non-cash
/// entry, or a cash entry without an amount — since a silently skipped row
/// understates taxable income. The node `id` is a relay blob
/// (`InvestActivityCashEntry:{"accountId":…,"activityEntryId":…,"isCredit":…}`,
/// observed live); the row carries the decoded `activityEntryId`.
fn dividend_row(v: &Value) -> Result<Value, CliError> {
    let typename = parse::opt_string(v, "__typename").unwrap_or_default();
    if typename != "InvestActivityCashEntry" {
        return Err(CliError::Upstream(format!(
            "M1's dividend filter returned a `{typename}` entry, not a cash entry — \
             the activity shape changed; see docs/api.md"
        )));
    }
    let raw_id = parse::id(v, "id")?;
    let id = parse::decode_relay_blob(&raw_id)
        .and_then(|b| parse::opt_string(&b, "activityEntryId"))
        .unwrap_or(raw_id);
    let amount = parse::money_at(v, "amount")
        .ok_or_else(|| CliError::Upstream(format!("M1 dividend entry `{id}` has no amount")))?;

    let mut row = json!({ "id": id });
    if let Some(date) = parse::date_at(v, &["date"]) {
        row["date"] = json!(date);
    }
    if let Some(symbol) = v
        .get("cashSecurity")
        .and_then(|s| parse::opt_string(s, "symbol"))
    {
        row["symbol"] = json!(symbol);
    }
    row["amount"] = serde_json::to_value(&amount).map_err(|e| {
        CliError::Upstream(format!(
            "M1 dividend entry `{id}`: amount not serializable: {e}"
        ))
    })?;
    if let Some(desc) =
        parse::opt_string(v, "description").or_else(|| parse::opt_string(v, "title"))
    {
        row["description"] = json!(desc);
    }
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> Value {
        json!({
            "__typename": "InvestActivityCashEntry",
            // base64 of `InvestActivityCashEntry:{"accountId":"acct-000000001","activityEntryId":"act-000000001","isCredit":true}`
            "id": "SW52ZXN0QWN0aXZpdHlDYXNoRW50cnk6eyJhY2NvdW50SWQiOiJhY2N0LTAwMDAwMDAwMSIsImFjdGl2aXR5RW50cnlJZCI6ImFjdC0wMDAwMDAwMDEiLCJpc0NyZWRpdCI6dHJ1ZX0=",
            "date": "2026-06-30T04:00:00.000Z",
            "title": "Dividend",
            "description": "",
            "amount": 1.25,
            "cashSecurity": { "symbol": "VTI" }
        })
    }

    #[test]
    fn a_dividend_row_carries_the_family_fields() {
        let row = dividend_row(&entry()).unwrap();
        assert_eq!(row["id"], json!("act-000000001"));
        assert_eq!(row["date"], json!("2026-06-30"));
        assert_eq!(row["symbol"], json!("VTI"));
        assert_eq!(row["amount"]["amount"], json!("1.25"));
        assert_eq!(row["amount"]["currency"], json!("USD"));
        // The empty description falls back to the title.
        assert_eq!(row["description"], json!("Dividend"));
    }

    #[test]
    fn a_non_cash_entry_fails_loudly() {
        let mut v = entry();
        v["__typename"] = json!("InvestActivityTradeEntry");
        assert_eq!(dividend_row(&v).unwrap_err().exit_code(), 5);
    }

    #[test]
    fn a_dividend_without_an_amount_fails_loudly() {
        let mut v = entry();
        v.as_object_mut().unwrap().remove("amount");
        assert_eq!(dividend_row(&v).unwrap_err().exit_code(), 5);
    }

    #[test]
    fn the_filter_carries_the_range_bounds() {
        let r = RangeArgs {
            since: Some("2026-01-01".into()),
            until: Some("2026-12-31".into()),
            limit: None,
        };
        assert_eq!(
            filter_for(&r),
            json!({
                "includeCategoryDividend": true,
                "fromDate": "2026-01-01",
                "toDate": "2026-12-31"
            })
        );
        assert_eq!(
            filter_for(&RangeArgs::default()),
            json!({ "includeCategoryDividend": true })
        );
    }

    #[test]
    fn rows_merge_newest_first_and_the_limit_applies_after() {
        let rows = vec![
            json!({ "date": "2026-03-01" }),
            json!({ "date": "2026-06-30" }),
            json!({ "date": "2026-04-15" }),
        ];
        let r = RangeArgs {
            since: None,
            until: None,
            limit: Some(2),
        };
        let out = finish(rows, &r);
        assert_eq!(
            out,
            vec![
                json!({ "date": "2026-06-30" }),
                json!({ "date": "2026-04-15" })
            ]
        );
    }
}
