//! `m1f lots list` — per-lot cost basis, the reason this CLI exists.
//!
//! `AccountTaxLots` is the richest tax surface M1 exposes: acquisition date,
//! cost basis, realized gain/loss split by holding term, and wash-sale data
//! per lot — strictly more than the 1099 PDF gives you for Form 8949.
//!
//! Two caveats worth knowing when reading the output:
//! - **The pre-2023 Apex gap.** Lots closed before M1's 2023 move to
//!   self-clearing live at Apex, not in M1's data (docs/api.md).
//! - **`--since`/`--until` key off the date that matters for each lot:** the
//!   **sale** date for a closed lot (what a Form 8949 line is dated by) and the
//!   **acquisition** date for a still-open lot. So
//!   `lots list --closed --since 2025-01-01 --until 2025-12-31` means "sold in
//!   2025", and correctly keeps a long-held lot bought years earlier but sold
//!   in the window — the case a naive acquisition-only filter would drop.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{emit, items, note_empty, table_view, Ctx};
use crate::{graphql, parse};

const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;

#[derive(clap::Args, Debug)]
pub struct LotsArgs {
    /// Only open lots (still held).
    #[arg(long, conflicts_with = "closed")]
    pub open: bool,

    /// Only closed lots (sold — the ones Form 8949 cares about).
    #[arg(long)]
    pub closed: bool,

    #[command(flatten)]
    pub range: RangeArgs,
}

pub fn list(ctx: &Ctx, args: &LotsArgs) -> Result<(), CliError> {
    args.range.validate()?;
    let account = ctx.account()?;
    // `lotType` is required by the resolver (verified live) and has exactly
    // two members, so "all lots" means two queries, merged.
    let lot_types: &[&str] = match (args.open, args.closed) {
        (true, _) => &["OPEN"],
        (_, true) => &["CLOSED"],
        _ => &["OPEN", "CLOSED"],
    };

    // A date window forces fetching every page before filtering (the filter is
    // client-side), so early-stopping on --limit is only safe with no window;
    // there, shrink `first` and stop once enough rows are in hand, sparing this
    // rate-limited API up to 40 needless round trips for `lots list --limit 5`.
    let has_window = args.range.since.is_some() || args.range.until.is_some();
    let limit = args.range.limit.map(|n| n as usize);
    let page_size = match (has_window, limit) {
        (false, Some(n)) => (n as u32).clamp(1, PAGE_SIZE),
        _ => PAGE_SIZE,
    };

    const PATH: &[&str] = &["node", "taxLots"];
    let mut rows: Vec<Value> = Vec::new();
    let mut truncated = false;
    'types: for lot_type in lot_types {
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let vars = json!({
                "accountId": account,
                "first": page_size,
                "after": cursor,
                "lotType": lot_type,
            });
            let data = ctx.read(|c| {
                c.execute(
                    graphql::ACCOUNT_TAX_LOTS,
                    vars.clone(),
                    Some("AccountTaxLots"),
                )
            })?;
            parse::require_node(&data)?;
            let container = parse::at(&data, PATH)?.clone();
            for node in parse::nodes(&data, PATH)? {
                let mut dto = lot_dto(&node)?;
                dto["status"] = json!(lot_type);
                rows.push(dto);
            }
            pages += 1;
            // With no date window, once we hold enough rows to satisfy --limit
            // there is nothing more to fetch.
            if !has_window && limit.is_some_and(|n| rows.len() >= n) {
                break 'types;
            }
            let next = parse::next_cursor(&container);
            if next.is_none() || next == cursor {
                break;
            }
            cursor = next;
            if pages >= MAX_PAGES {
                truncated = true;
                break;
            }
        }
    }
    if truncated && !ctx.common.quiet {
        // `AccountTaxLots` has no server-side date filter (args are `first`,
        // `after`, `lotType`), so --since/--until can't reduce what is fetched;
        // name the levers that actually do.
        eprintln!(
            "stopped after {MAX_PAGES} pages per lot type — this lot list is INCOMPLETE. \
             Narrow with --open/--closed, or raise the page cap."
        );
    }

    let rows: Vec<Value> = rows
        .into_iter()
        .filter(|r| in_lots_window(r, &args.range))
        .take(limit.unwrap_or(usize::MAX))
        .collect();
    if rows.is_empty() {
        note_empty(ctx, "tax lots");
    }
    // `truncated` rides in the DTO so a --json consumer building Form 8949 can
    // tell a complete lot set from a silently-capped prefix — a distinction
    // stderr can't carry (and --quiet hides). Never omit it: a machine reader
    // must be able to trust `false` means complete.
    emit(
        ctx,
        "lot-list",
        json!({ "items": rows, "truncated": truncated }),
        |v| {
            output::table(&table_view(
                &items(v, "items"),
                &[
                    "symbol",
                    "status",
                    "quantity",
                    "acquired",
                    "cost_basis",
                    "term",
                    "closed",
                    "realized_gain",
                    "wash_sale",
                ],
            ));
        },
    );
    Ok(())
}

fn lot_dto(v: &Value) -> Result<Value, CliError> {
    let mut dto = json!({});
    if let Some(sym) = parse::opt_string(v, "symbol") {
        dto["symbol"] = json!(sym);
    }
    dto["id"] = json!(parse::id(v, "id")?);
    if let Some(cusip) = parse::opt_string(v, "cusip") {
        dto["cusip"] = json!(cusip);
    }
    // Share counts stay plain string decimals, never money.
    if let Some(q) = parse::decimal_string(v, "quantity") {
        dto["quantity"] = json!(q);
    }
    if let Some(acquired) = v.get("acquisitionDate").and_then(parse::iso_date) {
        dto["acquired"] = json!(acquired);
    }
    if let Some(cb) = parse::money_at(v, "costBasis") {
        dto["cost_basis"] = serde_json::to_value(cb).unwrap_or(Value::Null);
    }
    if let Some(term) = parse::opt_string(v, "shortLongTermHolding") {
        dto["term"] = json!(term);
    }
    if let Some(closed) = v.get("closeDate").and_then(parse::iso_date) {
        dto["closed"] = json!(closed);
    }
    // Realized gain arrives split by holding term; a lot realizes under one
    // term, so surface whichever side is present (and both, if M1 ever
    // populates both) plus the parts under their own keys.
    let short = parse::money_at(v, "shortTermRealizedGainLoss");
    let long = parse::money_at(v, "longTermRealizedGainLoss");
    if let Some(s) = &short {
        dto["realized_gain_short"] = serde_json::to_value(s.clone()).unwrap_or(Value::Null);
    }
    if let Some(l) = &long {
        dto["realized_gain_long"] = serde_json::to_value(l.clone()).unwrap_or(Value::Null);
    }
    if let Some(total) = combined_gain(short, long) {
        dto["realized_gain"] = serde_json::to_value(total).unwrap_or(Value::Null);
    }
    if let Some(g) = parse::money_at(v, "unrealizedGainLoss") {
        dto["unrealized_gain"] = serde_json::to_value(g).unwrap_or(Value::Null);
    }
    if let Some(wash) = v.get("washSaleIndicator").and_then(Value::as_bool) {
        dto["wash_sale"] = json!(wash);
    }
    if let Some(dis) = parse::money_at(v, "disallowedWashSaleAmount") {
        dto["disallowed_wash_sale"] = serde_json::to_value(dis).unwrap_or(Value::Null);
    }
    Ok(dto)
}

/// Whether a lot falls inside the `--since`/`--until` window, keyed off the
/// date that actually matters for it: the **sale** date for a closed lot (Form
/// 8949 lines are dated by sale), the **acquisition** date for a still-open
/// lot. A lot with neither date is kept (filtered only by `--limit`), matching
/// how undated rows are treated elsewhere.
fn in_lots_window(row: &Value, range: &RangeArgs) -> bool {
    let key_date = row
        .get("closed")
        .and_then(Value::as_str)
        .or_else(|| row.get("acquired").and_then(Value::as_str));
    let after = range
        .since
        .as_deref()
        .zip(key_date)
        .map(|(s, d)| d >= s)
        .unwrap_or(true);
    let before = range
        .until
        .as_deref()
        .zip(key_date)
        .map(|(u, d)| d <= u)
        .unwrap_or(true);
    after && before
}

/// One realized-gain figure for the table column: the populated side, or their
/// sum if M1 ever fills both. Exact string-decimal arithmetic is overkill for
/// a display column that also emits the exact parts, but the sum must not be
/// done in floats — so when both are present and nonzero we only combine
/// values that parse exactly.
fn combined_gain(
    short: Option<pk_cli_core::Money>,
    long: Option<pk_cli_core::Money>,
) -> Option<pk_cli_core::Money> {
    let is_zero = |m: &pk_cli_core::Money| {
        m.amount
            .trim_start_matches('-')
            .chars()
            .all(|c| c == '0' || c == '.')
    };
    match (short, long) {
        (Some(s), None) => Some(s),
        (None, Some(l)) => Some(l),
        (Some(s), Some(l)) if is_zero(&l) => Some(s),
        (Some(s), Some(l)) if is_zero(&s) => Some(l),
        // Both populated and nonzero: don't guess — emit the parts only.
        (Some(_), Some(_)) => None,
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_lot() -> Value {
        json!({
            "id": "lot-1", "symbol": "VOO", "cusip": "00000DUMMY",
            "acquisitionDate": "2026-03-02", "quantity": 1.25,
            "costBasis": 500.0, "shortLongTermHolding": "SHORT",
            "closeDate": "2026-07-15",
            "shortTermRealizedGainLoss": 25.5, "longTermRealizedGainLoss": 0.0,
            "unrealizedGainLoss": 0.0,
            "washSaleIndicator": false, "disallowedWashSaleAmount": 0.0
        })
    }

    #[test]
    fn lot_dto_maps_the_8949_fields() {
        let dto = lot_dto(&full_lot()).unwrap();
        assert_eq!(dto["symbol"], json!("VOO"));
        assert_eq!(dto["quantity"], json!("1.25"));
        assert_eq!(dto["acquired"], json!("2026-03-02"));
        assert_eq!(dto["cost_basis"]["amount"], json!("500.00"));
        assert_eq!(dto["term"], json!("SHORT"));
        assert_eq!(dto["closed"], json!("2026-07-15"));
        assert_eq!(dto["realized_gain"]["amount"], json!("25.50"));
        assert_eq!(dto["wash_sale"], json!(false));
    }

    #[test]
    fn an_open_lot_omits_the_realized_fields() {
        let dto = lot_dto(&json!({
            "id": "lot-2", "symbol": "VTI", "quantity": 2.0,
            "acquisitionDate": "2026-05-01", "costBasis": 400.0,
            "unrealizedGainLoss": 12.0
        }))
        .unwrap();
        assert!(dto.get("closed").is_none());
        assert!(dto.get("realized_gain").is_none());
        assert_eq!(dto["unrealized_gain"]["amount"], json!("12.00"));
    }

    #[test]
    fn a_wash_sale_lot_carries_the_disallowed_amount() {
        let dto = lot_dto(&json!({
            "id": "lot-3", "washSaleIndicator": true,
            "disallowedWashSaleAmount": 13.13
        }))
        .unwrap();
        assert_eq!(dto["wash_sale"], json!(true));
        assert_eq!(dto["disallowed_wash_sale"]["amount"], json!("13.13"));
    }

    #[test]
    fn both_terms_populated_and_nonzero_emits_parts_but_no_guessed_total() {
        let dto = lot_dto(&json!({
            "id": "lot-4",
            "shortTermRealizedGainLoss": 5.0,
            "longTermRealizedGainLoss": 7.0
        }))
        .unwrap();
        assert!(dto.get("realized_gain").is_none());
        assert_eq!(dto["realized_gain_short"]["amount"], json!("5.00"));
        assert_eq!(dto["realized_gain_long"]["amount"], json!("7.00"));
    }

    #[test]
    fn a_negative_realized_loss_survives() {
        let dto = lot_dto(&json!({
            "id": "lot-5", "shortTermRealizedGainLoss": -3.25
        }))
        .unwrap();
        assert_eq!(dto["realized_gain"]["amount"], json!("-3.25"));
    }

    #[test]
    fn a_missing_id_fails_loudly() {
        assert_eq!(
            lot_dto(&json!({ "symbol": "X" })).unwrap_err().exit_code(),
            5
        );
    }

    fn window(since: &str, until: &str) -> RangeArgs {
        RangeArgs {
            since: Some(since.into()),
            until: Some(until.into()),
            limit: None,
        }
    }

    #[test]
    fn closed_lots_are_windowed_by_sale_date_not_acquisition() {
        // Bought in 2019, sold in 2025 — a long-term holding. A 2025 window
        // must KEEP it (sold in 2025), which acquisition-date filtering would
        // wrongly drop.
        let closed_2025 = json!({ "acquired": "2019-06-01", "closed": "2025-03-10" });
        assert!(in_lots_window(
            &closed_2025,
            &window("2025-01-01", "2025-12-31")
        ));

        // Bought in 2025 but not yet sold in 2025 (closed in 2026): a 2025
        // "sold in" window must EXCLUDE it.
        let closed_2026 = json!({ "acquired": "2025-02-01", "closed": "2026-01-05" });
        assert!(!in_lots_window(
            &closed_2026,
            &window("2025-01-01", "2025-12-31")
        ));
    }

    #[test]
    fn open_lots_fall_back_to_acquisition_date() {
        let open = json!({ "acquired": "2025-05-01" }); // no `closed`
        assert!(in_lots_window(&open, &window("2025-01-01", "2025-12-31")));
        assert!(!in_lots_window(&open, &window("2024-01-01", "2024-12-31")));
    }

    #[test]
    fn a_lot_with_no_dates_is_kept() {
        assert!(in_lots_window(
            &json!({ "id": "x" }),
            &window("2025-01-01", "2025-12-31")
        ));
    }
}
