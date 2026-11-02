//! `m1f activity list` — trades, dividends, and transfers over a date window.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{done_paging, emit, items, note_empty, paginate, table_view, Ctx};
use crate::{graphql, parse};

/// Ceiling on cursor pages per invocation.
///
/// A bound rather than "follow every cursor" because a broken `pageInfo` (or a
/// cursor that never advances) would otherwise spin forever against a
/// rate-limited API. Hitting the ceiling is reported, not silently truncated.
const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;
    let account = ctx.account()?;
    let (rows, truncated) = fetch(ctx, &account, range)?;

    if truncated && !ctx.common.quiet {
        eprintln!(
            "stopped after {MAX_PAGES} pages — narrow the window with --since/--until \
             or raise --limit"
        );
    }

    let rows = paginate(rows, "date", range);
    if rows.is_empty() {
        note_empty(ctx, "activity");
    }
    // `truncated` rides in the DTO (not just stderr) so a --json consumer can
    // tell a complete history from a page-capped prefix.
    emit(
        ctx,
        "activity-list",
        json!({ "items": rows, "truncated": truncated }),
        |v| {
            output::table(&table_view(
                &items(v, "items"),
                &["date", "type", "symbol", "description", "amount"],
            ));
        },
    );
    Ok(())
}

/// One account's activity rows, newest first: every page back past
/// `--since` (or until `--limit` rows are in hand with no `--since`), and
/// whether the page ceiling stopped the walk first.
pub fn fetch(ctx: &Ctx, account: &str, range: &RangeArgs) -> Result<(Vec<Value>, bool), CliError> {
    let page_size = range.limit.map(|n| n.min(PAGE_SIZE)).unwrap_or(PAGE_SIZE);
    let mut cursor: Option<String> = None;
    let mut rows: Vec<Value> = Vec::new();
    let mut pages = 0usize;
    let mut truncated = false;

    loop {
        let vars = json!({
            "accountId": account,
            "first": page_size,
            "after": cursor,
        });
        // Activity hangs off `investActivity` (schema-verified), not off the
        // account directly.
        const PATH: &[&str] = &["node", "investActivity", "activity"];
        let data =
            ctx.read(|c| c.execute(graphql::ACTIVITY, vars.clone(), Some("InvestActivityById")))?;
        parse::require_node(&data)?;
        let container = parse::at(&data, PATH)?.clone();
        for node in parse::nodes(&data, PATH)? {
            rows.push(activity_dto(&node)?);
        }
        pages += 1;

        let next = parse::next_cursor(&container);
        // A cursor that repeats itself is a provider bug that would otherwise
        // loop forever; treat it as the end of the connection.
        if next.is_some() && next == cursor {
            break;
        }
        cursor = next;
        if cursor.is_none() || done_paging(range, &rows) {
            break;
        }
        if pages >= MAX_PAGES {
            truncated = true;
            break;
        }
    }
    Ok((rows, truncated))
}

pub(crate) fn activity_dto(v: &Value) -> Result<Value, CliError> {
    let mut dto = json!({ "id": parse::id(v, "id")? });
    if let Some(date) = parse::date_at(v, &["date", "createdAt", "settledAt", "timestamp"]) {
        dto["date"] = json!(date);
    }
    // `InvestActivityEntry` is an interface (7 implementations, schema-
    // verified), so the kind arrives as `__typename`. The other spellings are
    // kept as fallbacks in case a flatter shape is returned.
    if let Some(kind) = parse::opt_string(v, "__typename")
        .map(|t| variant_label(&t))
        .or_else(|| parse::opt_string(v, "type"))
        .or_else(|| parse::opt_string(v, "activityType"))
    {
        dto["type"] = json!(kind);
    }
    // `title` is the short human label ("Dividend"); `description` adds detail.
    // Prefer the richer one but fall back to the other.
    if let Some(desc) =
        parse::opt_string(v, "description").or_else(|| parse::opt_string(v, "title"))
    {
        dto["description"] = json!(desc);
    }
    // Trade/Cash/Position variants each carry their security under a different
    // reference field, all shaped `{ symbol }`.
    if let Some(symbol) = ["tradeSecurity", "cashSecurity", "positionSecurity"]
        .iter()
        .find_map(|k| v.get(k).and_then(|s| parse::opt_string(s, "symbol")))
    {
        dto["symbol"] = json!(symbol);
    }
    if let Some(amount) = parse::money_at(v, "amount") {
        dto["amount"] = serde_json::to_value(amount).unwrap_or(Value::Null);
    }
    // Only the Trade variant carries a share price.
    if let Some(price) = parse::money_at(v, "sharePrice") {
        dto["share_price"] = serde_json::to_value(price).unwrap_or(Value::Null);
    }
    Ok(dto)
}

/// Turn a union variant type name into something worth putting in a column:
/// `InvestActivityTradeSummaryEntry` → `TradeSummary`.
///
/// Falls back to the raw name, so an unrecognized fifth variant shows up
/// visibly rather than as a blank cell.
fn variant_label(typename: &str) -> String {
    typename
        .strip_prefix("InvestActivity")
        .and_then(|t| t.strip_suffix("Entry"))
        .filter(|t| !t.is_empty())
        .unwrap_or(typename)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn activity_dto_normalizes_a_timestamp_to_an_iso_date() {
        let v = json!({
            "__typename": "InvestActivityCashEntry",
            "id": "a1", "createdAt": "2026-08-11T14:03:00Z",
            "description": "VOO dividend", "amount": 12.34
        });
        let dto = activity_dto(&v).unwrap();
        assert_eq!(dto["date"], json!("2026-08-11"));
        assert_eq!(dto["amount"]["amount"], json!("12.34"));
        assert_eq!(dto["type"], json!("Cash"));
    }

    #[test]
    fn a_negative_amount_is_preserved() {
        let dto = activity_dto(&json!({ "id": "a", "amount": "-25.00" })).unwrap();
        assert_eq!(dto["amount"]["amount"], json!("-25.00"));
    }
}

#[cfg(test)]
mod variant_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn variant_labels_are_readable() {
        assert_eq!(variant_label("InvestActivityTradeEntry"), "Trade");
        assert_eq!(
            variant_label("InvestActivityTradeSummaryEntry"),
            "TradeSummary"
        );
        assert_eq!(variant_label("InvestActivityCashEntry"), "Cash");
        assert_eq!(variant_label("InvestActivityPositionEntry"), "Position");
    }

    #[test]
    fn an_unknown_variant_stays_visible() {
        // A fifth variant must not render as an empty cell.
        assert_eq!(variant_label("SomethingElse"), "SomethingElse");
        assert_eq!(variant_label("InvestActivityEntry"), "InvestActivityEntry");
    }

    #[test]
    fn only_the_trade_variant_carries_a_share_price() {
        let trade = activity_dto(&json!({
            "__typename": "InvestActivityTradeEntry", "id": "a", "sharePrice": 200.0
        }))
        .unwrap();
        assert_eq!(trade["share_price"]["amount"], json!("200.00"));

        let cash =
            activity_dto(&json!({ "__typename": "InvestActivityCashEntry", "id": "b" })).unwrap();
        assert!(cash.get("share_price").is_none());
    }
}
