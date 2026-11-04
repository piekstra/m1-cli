//! `m1f trading` — what is queued in an account and when it trades: sell and
//! buy orders, rebalances, the auto-invest setting, the next trade window,
//! estimated trades, cash available for withdrawal and pending transfers.
//!
//! Unlike the other reads, this one keeps every key in the DTO and writes `null`
//! for a figure M1 did not give. "M1 gave no list of sell orders" and "no sell
//! orders" are different answers, and a missing figure must not read as zero.
//!
//! Schema-verified, not yet exercised live (docs/api.md, "Trading status").

use pk_cli_core::{output, CliError};
use serde_json::{json, Value};

use super::{accounts, emit, items, note_empty, table_view, Ctx};
use crate::{graphql, parse};

const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;

/// Every field the query selects at the top of the account. GraphQL answers a
/// selected field even when it is null, so a missing key is a shape change.
/// Without this, a renamed `maxCashThreshold` would read as auto-invest off.
const SELECTED: [&str; 18] = [
    "registration",
    "status",
    "isLiquidating",
    "isTradingPaused",
    "tradingPause",
    "maxCashThreshold",
    "autoInvestTriggerMinimum",
    "trading",
    "portfolioSlicesWithSellOrders",
    "portfolioSlicesWithBuyOrders",
    "portfolioSlicesWithRebalances",
    "rootPortfolioSlice",
    "imminentPendingCashFlowForOrders",
    "estimatedTrading",
    "balance",
    "hasPendingTransferInstances",
    "pendingTransferInstanceSummary",
    "pendingTransferInstances",
];

const ORDER_COLUMNS: [&str; 7] = [
    "kind",
    "name",
    "symbol",
    "amount",
    "value",
    "locked",
    "lock_reason",
];

const TRANSFER_COLUMNS: [&str; 9] = [
    "title",
    "status",
    "amount",
    "start_date",
    "to",
    "is_check",
    "depends_on_sells",
    "ira_distribution_reason",
    "timing_description",
];

pub fn show(ctx: &Ctx) -> Result<(), CliError> {
    let rows = collect(
        ctx.selected_account(),
        || accounts::scope(ctx, None),
        |account| fetch_node(ctx, account),
    )?;
    if rows.is_empty() {
        note_empty(ctx, "accounts");
    }
    if !ctx.common.quiet {
        for row in rows.iter().filter(|r| r["estimated"]["truncated"] == true) {
            eprintln!(
                "{}: the estimated trades listed are fewer than M1's count of them",
                row["id"].as_str().unwrap_or_default()
            );
        }
    }
    emit(ctx, "account-trading", json!({ "accounts": rows }), render);
    Ok(())
}

/// The DTOs for a selection: the selected account (flag, env or config, as
/// `holdings list` does), or every account on the login when nothing is selected.
fn collect(
    selected: Option<String>,
    scope: impl FnOnce() -> Result<Vec<accounts::AccountRef>, CliError>,
    mut fetch: impl FnMut(&str) -> Result<Value, CliError>,
) -> Result<Vec<Value>, CliError> {
    let ids: Vec<String> = match selected {
        Some(account) => vec![account],
        None => scope()?.into_iter().map(|a| a.id).collect(),
    };
    ids.iter().map(|id| account_dto(&fetch(id)?)).collect()
}

/// One account's node, with every page of its estimated trades.
pub fn fetch_node(ctx: &Ctx, account: &str) -> Result<Value, CliError> {
    let vars = json!({ "accountId": account, "first": PAGE_SIZE });
    let data = ctx.read(|c| {
        c.execute(
            graphql::ACCOUNT_TRADING,
            vars.clone(),
            Some("AccountTrading"),
        )
    })?;
    parse::require_node(&data)?;
    let mut node = parse::at(&data, &["node"])?.clone();
    follow_estimates(&mut node, |side, after| {
        let vars = page_vars(account, side, after);
        let data = ctx.read(|c| {
            c.execute(
                graphql::ACCOUNT_ESTIMATED_TRADES,
                vars.clone(),
                Some("AccountEstimatedTrades"),
            )
        })?;
        parse::require_node(&data)?;
        Ok(parse::at(&data, &["node", "estimatedTrading", side])?.clone())
    })?;
    Ok(node)
}

/// `AccountEstimatedTrades`'s variables for the next page of one side. The other
/// side stays out of the response, and its cursor stays null.
fn page_vars(account: &str, side: &str, after: &str) -> Value {
    json!({
        "accountId": account,
        "first": PAGE_SIZE,
        "sellsAfter": (side == "sells").then_some(after),
        "buysAfter": (side == "buys").then_some(after),
        "withSells": side == "sells",
        "withBuys": side == "buys",
    })
}

/// Append the later pages of each estimated-trades connection to its first page.
fn follow_estimates(
    node: &mut Value,
    mut next_page: impl FnMut(&str, &str) -> Result<Value, CliError>,
) -> Result<(), CliError> {
    for side in ["sells", "buys"] {
        let Some(conn) = node
            .get_mut("estimatedTrading")
            .and_then(|e| e.get_mut(side))
        else {
            continue;
        };
        let mut cursor = parse::next_cursor(conn);
        let mut pages = 1;
        while let Some(after) = cursor.take().filter(|_| pages < MAX_PAGES) {
            let page = next_page(side, &after)?;
            pages += 1;
            if let (Some(rows), Some(more)) = (
                conn.get_mut("edges").and_then(Value::as_array_mut),
                page.get("edges").and_then(Value::as_array),
            ) {
                rows.extend(more.iter().cloned());
            }
            cursor = parse::next_cursor(&page).filter(|next| *next != after);
        }
    }
    Ok(())
}

/// Map an `Account` node to one entry of the `account-trading/v1` DTO.
pub fn account_dto(node: &Value) -> Result<Value, CliError> {
    for key in SELECTED {
        parse::at(node, &[key])?;
    }
    let acct = accounts::AccountRef::from_node(node)?;
    let cash = child(child(node, "balance"), "cash");
    let root = child(child(node, "rootPortfolioSlice"), "orderStatus");
    Ok(json!({
        "id": acct.id,
        "name": acct.name,
        "account_type": acct.account_type(),
        "registration": acct.registration,
        "is_retirement": acct.is_retirement,
        "status": text(node, "status"),
        "is_liquidating": flag(node, "isLiquidating"),
        "trading_paused": flag(node, "isTradingPaused"),
        "trading_pause": object_or_null(child(node, "tradingPause"), |pause| json!({
            "title": text(pause, "title"),
            "description": text(pause, "description"),
        })),
        "auto_invest": auto_invest(node),
        "trading": object_or_null(child(node, "trading"), |t| json!({
            "next_window": text(t, "nextWindowForAccount"),
            "next_time": time(t, "nextTradingTime"),
            "in_progress": flag(t, "isInProgress"),
            "in_progress_window": text(t, "inProgressWindowForAccount"),
            "has_access_to_next_afternoon_window": flag(t, "hasAccessToNextAfternoonWindow"),
        })),
        "orders": {
            "sells": rows(node, "portfolioSlicesWithSellOrders", |s| slice_row(s, "orderStatus")),
            "buys": rows(node, "portfolioSlicesWithBuyOrders", |s| slice_row(s, "orderStatus")),
            "rebalances": rows(node, "portfolioSlicesWithRebalances", |s| {
                slice_row(s, "rebalanceStatus")
            }),
            "root_order": money(child(root, "order"), "cashFlow"),
            "net_descendant_sell": money(root, "netDescendantSellOrderAmount"),
            "net_descendant_buy": money(root, "netDescendantBuyOrderAmount"),
            "imminent_cash_flow": money(node, "imminentPendingCashFlowForOrders"),
        },
        "estimated": estimated(child(node, "estimatedTrading"))?,
        "cash": {
            "available": money(cash, "available"),
            "available_for_withdrawal": money(cash, "availableForWithdrawal"),
        },
        "total_value": accounts::total_value(node),
        "pending_transfers": {
            "has_pending": flag(node, "hasPendingTransferInstances"),
            "summary": text(node, "pendingTransferInstanceSummary"),
            "items": rows(node, "pendingTransferInstances", transfer_row),
        },
    }))
}

/// `on` is inferred from the schema's description of `maxCashThreshold`: "When
/// null, the max cash threshold is disabled". A threshold of 0 is on. Not yet
/// confirmed on a real account (docs/api.md).
fn auto_invest(node: &Value) -> Value {
    let threshold = child(node, "maxCashThreshold");
    json!({
        "on": !threshold.is_null(),
        "threshold": parse::money(threshold),
        "trigger_minimum": money(node, "autoInvestTriggerMinimum"),
    })
}

/// One slice with an order or a rebalance set. `lock` names which status says
/// whether it is locked: a rebalance's lock is not its order's. A null element of
/// M1's list keeps its row, so the count of what is queued stays right.
fn slice_row(slice: &Value, lock: &str) -> Value {
    let to = child(slice, "to");
    let status = child(slice, lock);
    json!({
        "name": text(to, "name"),
        "symbol": text(to, "symbol"),
        "is_root": flag(slice, "isRootSlice"),
        "amount": money(child(child(slice, "orderStatus"), "order"), "cashFlow"),
        "value": money(child(slice, "value"), "total"),
        "locked": flag(status, "isLocked"),
        "lock_reason": text(status, "lockReason"),
    })
}

fn estimated(est: &Value) -> Result<Value, CliError> {
    if est.is_null() {
        return Ok(Value::Null);
    }
    let sells = estimate_rows(est, "sells")?;
    let buys = estimate_rows(est, "buys")?;
    let truncated = [("sells", &sells), ("buys", &buys)]
        .iter()
        .any(|(side, got)| {
            let held = got.as_array().map_or(0, Vec::len) as u64;
            child(child(est, side), "total")
                .as_u64()
                .is_some_and(|total| total > held)
        });
    Ok(json!({
        "has_trades": flag(est, "hasTrades"),
        "total_sell": money(est, "totalSellAmount"),
        "total_buy": money(est, "totalBuyAmount"),
        "last_estimated": time(est, "lastEstimatedTime"),
        "sells": sells,
        "buys": buys,
        "truncated": truncated,
    }))
}

/// A connection's rows, or null when M1 gave no edges: not the same as none.
fn estimate_rows(est: &Value, side: &str) -> Result<Value, CliError> {
    let conn = child(est, side);
    if conn.is_null() || conn.get("edges").is_some_and(Value::is_null) {
        return Ok(Value::Null);
    }
    let found = parse::nodes(est, &[side])?;
    Ok(Value::Array(found.iter().map(estimate_row).collect()))
}

/// `amount` is as M1 sends it: the schema does not say whether a sell's is
/// negative, so `is_buy` carries the direction and nothing is re-signed here.
fn estimate_row(v: &Value) -> Value {
    let of = child(v, "of");
    json!({
        "symbol": text(of, "symbol"),
        "name": text(of, "name"),
        "amount": money(v, "amount"),
        "is_buy": flag(v, "isBuy"),
        "pill": text(child(v, "pill"), "label"),
    })
}

fn transfer_row(v: &Value) -> Value {
    json!({
        "id": transfer_id(v),
        "status": text(child(v, "status"), "code"),
        "title": text(v, "title"),
        "description": text(v, "description"),
        "start_date": parse::date_at(v, &["startDate"]),
        "end_date": parse::date_at(v, &["endDate"]),
        "amount": money(v, "amount"),
        "is_liquidation": flag(v, "isLiquidation"),
        "is_check": flag(v, "isCheck"),
        "depends_on_sells": flag(v, "dependsOnSells"),
        "timing_description": text(v, "timingDescription"),
        "ira_distribution_reason": text(v, "iraDistributionReason"),
        "from": participant(child(v, "from")),
        "to": participant(child(v, "to")),
    })
}

/// `isCheck` is documented as a check sent from Spend Checking, so a check out
/// of an IRA may be told apart only by the receiving participant's type.
fn participant(v: &Value) -> Value {
    object_or_null(v, |p| {
        json!({
            "type": text(p, "transferParticipantType"),
            "name": text(p, "transferParticipantName"),
        })
    })
}

/// The inner id of a `TransferInstance:{"transferId":…}` blob, never the blob. An
/// id that is not one passes only while short enough not to be a blob of another
/// shape (the rule `documents.rs` holds its ids to).
fn transfer_id(v: &Value) -> Option<String> {
    let raw = parse::opt_string(v, "id")?;
    match parse::decode_relay_blob(&raw) {
        Some(inner) => parse::opt_string(&inner, "transferId"),
        None => Some(raw).filter(|id| id.len() <= 64),
    }
}

// ---- the text view ----------------------------------------------------------

fn render(v: &Value) {
    for (i, account) in items(v, "accounts").iter().enumerate() {
        if i > 0 {
            println!();
        }
        output::kv(&head(account), 0);
        println!("\nOrders:");
        output::table(&table_view(&order_rows(account), &ORDER_COLUMNS));
        println!("\nPending transfers:");
        output::table(&table_view(&transfer_rows(account), &TRANSFER_COLUMNS));
    }
}

/// The key/value block. A figure M1 did not give shows as `-`, never as blank or 0.
fn head(a: &Value) -> Value {
    let orders = &a["orders"];
    let trading = &a["trading"];
    let estimated = &a["estimated"];
    let invest = &a["auto_invest"];
    let on = if invest["on"] == true { "on" } else { "off" };
    shown(json!({
        "id": a["id"],
        "name": a["name"],
        "registration": a["registration"],
        "status": a["status"],
        "is_liquidating": a["is_liquidating"],
        "trading_paused": a["trading_paused"],
        "pause_reason": a["trading_pause"]["title"],
        "auto_invest": on,
        "auto_invest_threshold": invest["threshold"],
        "auto_invest_trigger_minimum": invest["trigger_minimum"],
        "next_window": trading["next_window"],
        "next_time": trading["next_time"],
        "window_in_progress": trading["in_progress"],
        "in_progress_window": trading["in_progress_window"],
        "root_order": orders["root_order"],
        "net_descendant_sell": orders["net_descendant_sell"],
        "net_descendant_buy": orders["net_descendant_buy"],
        "imminent_cash_flow": orders["imminent_cash_flow"],
        "estimated_sell_total": estimated["total_sell"],
        "estimated_buy_total": estimated["total_buy"],
        "estimated_at": estimated["last_estimated"],
        "cash_available": a["cash"]["available"],
        "cash_available_for_withdrawal": a["cash"]["available_for_withdrawal"],
        "total_value": a["total_value"],
        "pending_transfers": a["pending_transfers"]["summary"],
    }))
}

/// Orders, then rebalances, then estimated trades, each row saying which. A list
/// M1 did not give gets a row saying so, or the table would read as nothing queued.
fn order_rows(a: &Value) -> Vec<Value> {
    let orders = &a["orders"];
    let estimated = &a["estimated"];
    let mut out = Vec::new();
    let mut add = |kind: &str, list: &Value| match list.as_array() {
        Some(found) => {
            for row in found {
                let mut row = row.clone();
                row["kind"] = json!(kind);
                out.push(shown(row));
            }
        }
        None => out.push(json!({ "kind": kind, "name": "M1 gave no list" })),
    };
    add("sell", &orders["sells"]);
    add("buy", &orders["buys"]);
    add("rebalance", &orders["rebalances"]);
    if !estimated.is_null() {
        add("estimated sell", &estimated["sells"]);
        add("estimated buy", &estimated["buys"]);
    }
    out
}

fn transfer_rows(a: &Value) -> Vec<Value> {
    match a["pending_transfers"]["items"].as_array() {
        Some(found) => found
            .iter()
            .map(|t| {
                let mut row = t.clone();
                row["to"] = t["to"]["name"].clone();
                shown(row)
            })
            .collect(),
        None => vec![json!({ "title": "M1 gave no list" })],
    }
}

/// An object's nulls as `-`, for display only.
fn shown(mut v: Value) -> Value {
    if let Some(fields) = v.as_object_mut() {
        for field in fields.values_mut().filter(|f| f.is_null()) {
            *field = json!("-");
        }
    }
    v
}

// ---- field readers: an absent or null field is null -------------------------

fn child<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn text(v: &Value, key: &str) -> Option<String> {
    parse::opt_string(v, key)
}

fn flag(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

fn money(v: &Value, key: &str) -> Option<pk_cli_core::Money> {
    parse::money_at(v, key)
}

/// A timestamp at full precision: the time of a trade window is the point of it.
fn time(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(parse::iso_or_rfc3339)
}

fn object_or_null(v: &Value, map: impl FnOnce(&Value) -> Value) -> Value {
    if v.is_null() {
        Value::Null
    } else {
        map(v)
    }
}

/// M1's list as rows, or null when M1 gave no list: not the same as an empty one.
fn rows(node: &Value, key: &str, row: impl Fn(&Value) -> Value) -> Value {
    match child(node, key).as_array() {
        Some(found) => Value::Array(found.iter().map(row).collect()),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(raw: &str) -> Value {
        let v: Value = serde_json::from_str(raw).expect("fixture parses");
        v["data"]["node"].clone()
    }

    fn queued() -> Value {
        fixture(include_str!("../../tests/fixtures/reads/trading.json"))
    }

    fn idle() -> Value {
        fixture(include_str!("../../tests/fixtures/reads/trading-idle.json"))
    }

    fn unavailable() -> Value {
        fixture(include_str!(
            "../../tests/fixtures/reads/trading-unavailable.json"
        ))
    }

    fn usd(amount: &str) -> Value {
        json!({ "amount": amount, "currency": "USD" })
    }

    // ---- a queued sell order ----

    #[test]
    fn a_queued_sell_order_shows_its_slice_signed_amount_and_lock() {
        let dto = account_dto(&queued()).unwrap();
        let sells = dto["orders"]["sells"].as_array().unwrap();
        assert_eq!(sells.len(), 2);
        assert_eq!(sells[0]["name"], "Example Total Market Fund");
        assert_eq!(sells[0]["symbol"], "XMPA");
        assert_eq!(sells[0]["amount"], usd("-750.50"));
        assert_eq!(sells[0]["value"], usd("1500.25"));
        assert_eq!(sells[0]["locked"], false);
        assert_eq!(sells[0]["lock_reason"], "UNLOCKED");
        // A pie has a name and no symbol.
        assert_eq!(sells[1]["name"], "Example Growth Pie");
        assert!(sells[1]["symbol"].is_null());
        assert_eq!(sells[1]["locked"], true);
        assert_eq!(sells[1]["lock_reason"], "LOCKED_BY_TRADING");
        assert_eq!(dto["orders"]["net_descendant_sell"], usd("-1000.00"));
        assert_eq!(dto["orders"]["imminent_cash_flow"], usd("-1000.00"));
    }

    #[test]
    fn a_buy_order_is_positive() {
        let dto = account_dto(&queued()).unwrap();
        assert_eq!(dto["orders"]["buys"][0]["amount"], usd("200.00"));
        assert_eq!(dto["orders"]["buys"][0]["symbol"], "XMPB");
    }

    /// M1 documents `netDescendant*` as leaving out an order on the slice itself,
    /// so a sale queued at the top of the pie shows only here.
    #[test]
    fn an_order_on_the_root_slice_is_not_lost() {
        let mut node = queued();
        node["rootPortfolioSlice"]["orderStatus"] = json!({
            "netDescendantSellOrderAmount": 0.0,
            "netDescendantBuyOrderAmount": 0.0,
            "order": { "cashFlow": -500.0 }
        });
        let dto = account_dto(&node).unwrap();
        assert_eq!(dto["orders"]["root_order"], usd("-500.00"));
        assert_eq!(dto["orders"]["net_descendant_sell"], usd("0.00"));
        assert_eq!(head(&dto)["root_order"], usd("-500.00"));
    }

    /// A rebalance has no amount, and its lock is `rebalanceStatus`: the fixture's
    /// `orderStatus` on the same slice says locked, by that same rebalance.
    #[test]
    fn a_rebalance_reads_its_own_lock_and_has_no_amount() {
        let dto = account_dto(&queued()).unwrap();
        let row = &dto["orders"]["rebalances"][0];
        assert_eq!(row["name"], "Example Income Pie");
        assert!(row["amount"].is_null());
        assert_eq!(row["locked"], false);
        assert_eq!(row["lock_reason"], "UNLOCKED");
        // A slice M1 cannot price right now has no value, not a zero one.
        assert!(row["value"].is_null());
    }

    #[test]
    fn estimated_trades_carry_their_totals_and_when_they_were_estimated() {
        let est = account_dto(&queued()).unwrap()["estimated"].clone();
        assert_eq!(est["has_trades"], true);
        assert_eq!(est["total_sell"], usd("1000.00"));
        assert_eq!(est["total_buy"], usd("200.00"));
        assert_eq!(est["last_estimated"], "2026-01-14T20:00:00.000Z");
        assert_eq!(est["sells"][0]["symbol"], "XMPA");
        // As M1 sent it: the direction is `is_buy`, nothing is re-signed.
        assert_eq!(est["sells"][0]["amount"], usd("750.50"));
        assert_eq!(est["sells"][0]["is_buy"], false);
        assert_eq!(est["sells"][1]["pill"], "Example note");
        assert_eq!(est["buys"][0]["is_buy"], true);
        assert_eq!(est["truncated"], false);
    }

    #[test]
    fn the_next_window_keeps_its_time_of_day() {
        let t = account_dto(&queued()).unwrap()["trading"].clone();
        assert_eq!(t["next_window"], "MORNING");
        assert_eq!(t["next_time"], "2026-01-15T14:30:00.000Z");
        assert_eq!(t["in_progress"], false);
        assert!(t["in_progress_window"].is_null());
        assert_eq!(t["has_access_to_next_afternoon_window"], false);
    }

    #[test]
    fn cash_available_for_withdrawal_of_zero_is_zero_not_null() {
        let dto = account_dto(&queued()).unwrap();
        assert_eq!(dto["cash"]["available"], usd("12.50"));
        assert_eq!(dto["cash"]["available_for_withdrawal"], usd("0.00"));
        assert_eq!(dto["total_value"], usd("5000.25"));
    }

    // ---- nothing queued ----

    #[test]
    fn nothing_queued_is_empty_lists_and_zero_totals() {
        let dto = account_dto(&idle()).unwrap();
        for list in ["sells", "buys", "rebalances"] {
            assert_eq!(dto["orders"][list], json!([]), "{list}");
        }
        assert_eq!(dto["estimated"]["has_trades"], false);
        assert_eq!(dto["estimated"]["sells"], json!([]));
        assert_eq!(dto["estimated"]["total_sell"], usd("0.00"));
        assert_eq!(dto["pending_transfers"]["has_pending"], false);
        assert_eq!(dto["pending_transfers"]["items"], json!([]));
        assert!(order_rows(&dto).is_empty());
        assert!(transfer_rows(&dto).is_empty());
    }

    // ---- auto-invest ----

    #[test]
    fn auto_invest_is_on_with_a_threshold() {
        let dto = account_dto(&queued()).unwrap();
        assert_eq!(dto["auto_invest"]["on"], true);
        assert_eq!(dto["auto_invest"]["threshold"], usd("100.00"));
        assert_eq!(dto["auto_invest"]["trigger_minimum"], usd("25.00"));
        assert_eq!(head(&dto)["auto_invest"], "on");
    }

    #[test]
    fn auto_invest_is_off_with_a_null_threshold() {
        let dto = account_dto(&idle()).unwrap();
        assert_eq!(dto["auto_invest"]["on"], false);
        assert!(dto["auto_invest"]["threshold"].is_null());
        assert_eq!(dto["auto_invest"]["trigger_minimum"], usd("25.00"));
        assert_eq!(head(&dto)["auto_invest"], "off");
    }

    /// The schema allows zero ("greater than or equal to zero"), and zero is on.
    #[test]
    fn a_threshold_of_zero_is_on() {
        let mut node = idle();
        node["maxCashThreshold"] = json!(0);
        let dto = account_dto(&node).unwrap();
        assert_eq!(dto["auto_invest"]["on"], true);
        assert_eq!(dto["auto_invest"]["threshold"], usd("0.00"));
    }

    /// A renamed field must not read as a setting the account does not have.
    #[test]
    fn a_missing_threshold_field_is_a_shape_change_not_off() {
        let mut node = idle();
        node.as_object_mut().unwrap().remove("maxCashThreshold");
        let err = account_dto(&node).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("maxCashThreshold"), "{err}");
    }

    // ---- a pending check ----

    #[test]
    fn a_pending_check_transfer_carries_what_it_waits_on() {
        let dto = account_dto(&queued()).unwrap();
        assert_eq!(dto["pending_transfers"]["has_pending"], true);
        assert_eq!(dto["pending_transfers"]["summary"], "1 transfer pending");
        let t = &dto["pending_transfers"]["items"][0];
        assert_eq!(t["id"], "act-000000020");
        assert_eq!(t["status"], "INITIATED");
        assert_eq!(t["title"], "Roth IRA to Example Custodian");
        assert_eq!(t["description"], "Rollover check");
        assert_eq!(t["start_date"], "2026-01-14");
        assert!(t["end_date"].is_null());
        assert_eq!(t["amount"], usd("1000.00"));
        assert_eq!(t["is_liquidation"], false);
        assert_eq!(t["is_check"], true);
        assert_eq!(t["depends_on_sells"], true);
        assert_eq!(t["timing_description"], "After the example sale settles");
        assert_eq!(t["ira_distribution_reason"], "ROLLOVER_TO_QUALIFIED_PLAN");
        assert_eq!(t["from"]["type"], "INVEST");
        assert_eq!(t["to"]["type"], "PHYSICAL_CHECK");
        assert_eq!(t["to"]["name"], "Example Custodian");
    }

    /// `isCheck` is documented for Spend Checking, so a check out of an IRA may
    /// say false. The receiving participant still says what it is.
    #[test]
    fn a_check_with_is_check_false_is_still_told_by_its_participant() {
        let mut node = queued();
        node["pendingTransferInstances"][0]["isCheck"] = json!(false);
        let dto = account_dto(&node).unwrap();
        let t = &dto["pending_transfers"]["items"][0];
        assert_eq!(t["is_check"], false);
        assert_eq!(t["to"]["type"], "PHYSICAL_CHECK");
    }

    #[test]
    fn a_transfer_of_unknown_amount_stays_null() {
        let mut node = queued();
        node["pendingTransferInstances"][0]["amount"] = Value::Null;
        let dto = account_dto(&node).unwrap();
        assert!(dto["pending_transfers"]["items"][0]["amount"].is_null());
    }

    #[test]
    fn a_transfer_id_blob_is_decoded_and_never_emitted() {
        // Decodes to `TransferInstance:{"transferId":"abc"}`.
        let blob = "VHJhbnNmZXJJbnN0YW5jZTp7InRyYW5zZmVySWQiOiJhYmMifQ==";
        let mut node = queued();
        node["pendingTransferInstances"][0]["id"] = json!(blob);
        let dto = account_dto(&node).unwrap();
        assert_eq!(dto["pending_transfers"]["items"][0]["id"], "abc");
        assert!(!dto.to_string().contains(blob));
    }

    #[test]
    fn an_undecodable_long_transfer_id_is_dropped() {
        let blob = "not-a-blob-".repeat(10);
        let mut node = queued();
        node["pendingTransferInstances"][0]["id"] = json!(blob);
        let dto = account_dto(&node).unwrap();
        assert!(dto["pending_transfers"]["items"][0]["id"].is_null());
        assert!(!dto.to_string().contains(&blob));
    }

    // ---- null stays null ----

    #[test]
    fn null_fields_stay_null_and_no_list_is_not_an_empty_list() {
        let dto = account_dto(&unavailable()).unwrap();
        assert!(dto["trading_paused"].is_null());
        assert!(dto["trading_pause"].is_null());
        assert!(dto["auto_invest"]["threshold"].is_null());
        assert!(dto["trading"].is_null());
        for list in ["sells", "buys", "rebalances"] {
            assert!(dto["orders"][list].is_null(), "{list}");
        }
        for figure in [
            "root_order",
            "net_descendant_sell",
            "net_descendant_buy",
            "imminent_cash_flow",
        ] {
            assert!(dto["orders"][figure].is_null(), "{figure}");
        }
        assert!(dto["estimated"].is_null());
        assert!(dto["cash"]["available"].is_null());
        assert!(dto["cash"]["available_for_withdrawal"].is_null());
        assert!(dto["total_value"].is_null());
        assert!(dto["pending_transfers"]["has_pending"].is_null());
        assert!(dto["pending_transfers"]["summary"].is_null());
        assert!(dto["pending_transfers"]["items"].is_null());
    }

    /// Every key is present either way, so a consumer tells null from absent.
    #[test]
    fn the_keys_are_the_same_with_or_without_data() {
        fn keys(v: &Value) -> Vec<String> {
            v.as_object().unwrap().keys().cloned().collect()
        }
        let full = account_dto(&queued()).unwrap();
        let empty = account_dto(&unavailable()).unwrap();
        assert_eq!(keys(&full), keys(&empty));
        for nested in ["auto_invest", "orders", "cash", "pending_transfers"] {
            assert_eq!(keys(&full[nested]), keys(&empty[nested]), "{nested}");
        }
    }

    #[test]
    fn the_view_shows_a_missing_figure_as_a_dash_and_says_when_no_list_came() {
        let dto = account_dto(&unavailable()).unwrap();
        let h = head(&dto);
        assert_eq!(h["cash_available"], "-");
        assert_eq!(h["next_window"], "-");
        assert_eq!(h["total_value"], "-");
        let rows = order_rows(&dto);
        assert_eq!(rows.len(), 3);
        assert!(
            rows.iter().all(|r| r["name"] == "M1 gave no list"),
            "{rows:?}"
        );
        assert_eq!(transfer_rows(&dto)[0]["title"], "M1 gave no list");
    }

    #[test]
    fn a_null_element_of_a_list_keeps_its_row() {
        let mut node = queued();
        node["portfolioSlicesWithSellOrders"] = json!([null]);
        let dto = account_dto(&node).unwrap();
        let sells = dto["orders"]["sells"].as_array().unwrap();
        assert_eq!(sells.len(), 1);
        assert!(sells[0]["amount"].is_null());
    }

    #[test]
    fn a_null_order_status_leaves_the_amount_and_lock_null() {
        let mut node = queued();
        node["portfolioSlicesWithSellOrders"][0]["orderStatus"] = Value::Null;
        let dto = account_dto(&node).unwrap();
        let row = &dto["orders"]["sells"][0];
        assert_eq!(row["name"], "Example Total Market Fund");
        assert!(row["amount"].is_null());
        assert!(row["locked"].is_null());
        assert!(row["lock_reason"].is_null());
    }

    #[test]
    fn an_account_m1_cannot_price_has_no_total_value() {
        let mut node = queued();
        node["balance"]["totalValue"] = json!({ "value": 0.0, "hasValue": false });
        assert!(account_dto(&node).unwrap()["total_value"].is_null());
    }

    #[test]
    fn a_paused_account_says_why() {
        let mut node = queued();
        node["isTradingPaused"] = json!(true);
        node["tradingPause"] = json!({ "title": "Example pause", "description": null });
        let dto = account_dto(&node).unwrap();
        assert_eq!(dto["trading_paused"], true);
        assert_eq!(dto["trading_pause"]["title"], "Example pause");
        assert!(dto["trading_pause"]["description"].is_null());
        assert_eq!(head(&dto)["pause_reason"], "Example pause");
    }

    // ---- the view ----

    #[test]
    fn the_orders_table_says_what_each_row_is() {
        let dto = account_dto(&queued()).unwrap();
        let rows = order_rows(&dto);
        let kinds: Vec<&str> = rows.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert_eq!(
            kinds,
            [
                "sell",
                "sell",
                "buy",
                "rebalance",
                "estimated sell",
                "estimated sell",
                "estimated buy"
            ]
        );
    }

    #[test]
    fn the_transfer_table_names_where_the_money_goes() {
        let dto = account_dto(&queued()).unwrap();
        let rows = transfer_rows(&dto);
        assert_eq!(rows[0]["to"], "Example Custodian");
        assert_eq!(rows[0]["is_check"], true);
        assert_eq!(rows[0]["end_date"], "-");
    }

    #[test]
    fn the_view_renders_every_fixture() {
        let accounts: Vec<Value> = [queued(), idle(), unavailable()]
            .iter()
            .map(|node| account_dto(node).unwrap())
            .collect();
        render(&json!({ "accounts": accounts }));
    }

    // ---- which accounts ----

    fn two_accounts() -> Vec<accounts::AccountRef> {
        ["acct-000000002", "acct-000000001"]
            .iter()
            .map(|id| accounts::AccountRef {
                id: (*id).into(),
                name: None,
                registration: None,
                is_retirement: false,
            })
            .collect()
    }

    fn node_for(id: &str) -> Value {
        let mut node = queued();
        node["id"] = json!(id);
        node
    }

    #[test]
    fn a_selected_account_reads_only_that_account() {
        let mut asked = Vec::new();
        let rows = collect(
            Some("acct-000000002".into()),
            || panic!("a selected account must not enumerate the login"),
            |a| {
                asked.push(a.to_string());
                Ok(node_for(a))
            },
        )
        .unwrap();
        assert_eq!(asked, ["acct-000000002"]);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["id"], "acct-000000002");
    }

    #[test]
    fn nothing_selected_covers_every_account() {
        let rows = collect(None, || Ok(two_accounts()), |a| Ok(node_for(a))).unwrap();
        let ids: Vec<&Value> = rows.iter().map(|r| &r["id"]).collect();
        assert_eq!(ids, ["acct-000000002", "acct-000000001"]);
    }

    // ---- estimated trades across pages ----

    fn page(symbols: &[&str], next: Option<&str>) -> Value {
        let edges: Vec<Value> = symbols
            .iter()
            .map(|s| {
                json!({ "node": { "amount": 1.0, "isBuy": false, "of": { "symbol": s, "name": s } } })
            })
            .collect();
        json!({
            "total": 3,
            "pageInfo": { "hasNextPage": next.is_some(), "endCursor": next },
            "edges": edges,
        })
    }

    #[test]
    fn later_pages_of_estimates_are_appended_side_by_side() {
        let mut node = queued();
        node["estimatedTrading"]["sells"] = page(&["XMPA", "XMPB"], Some("DUMMYCURSOR051"));
        let mut asked = Vec::new();
        follow_estimates(&mut node, |side, after| {
            asked.push(format!("{side}:{after}"));
            Ok(page(&["XMPC"], None))
        })
        .unwrap();
        // Buys had no next page, so only sells were asked for.
        assert_eq!(asked, ["sells:DUMMYCURSOR051"]);
        let dto = account_dto(&node).unwrap();
        let sells = dto["estimated"]["sells"].as_array().unwrap();
        assert_eq!(sells.len(), 3);
        assert_eq!(sells[2]["symbol"], "XMPC");
        assert_eq!(dto["estimated"]["truncated"], false);
    }

    #[test]
    fn a_later_page_asks_for_one_side_only() {
        let vars = page_vars("acct-000000002", "buys", "DUMMYCURSOR051");
        assert_eq!(vars["accountId"], "acct-000000002");
        assert_eq!(vars["buysAfter"], "DUMMYCURSOR051");
        assert!(vars["sellsAfter"].is_null());
        assert_eq!(vars["withBuys"], true);
        assert_eq!(vars["withSells"], false);
    }

    #[test]
    fn the_page_ceiling_says_the_rows_are_truncated() {
        let mut node = queued();
        node["estimatedTrading"]["sells"] = page(&["XMPA"], Some("DUMMYCURSOR051"));
        node["estimatedTrading"]["sells"]["total"] = json!(1000);
        let mut calls = 0;
        follow_estimates(&mut node, |_, _| {
            calls += 1;
            Ok(page(&["XMPB"], Some(&format!("DUMMYCURSOR{calls:03}"))))
        })
        .unwrap();
        assert_eq!(calls, MAX_PAGES - 1);
        let dto = account_dto(&node).unwrap();
        assert_eq!(dto["estimated"]["truncated"], true);
    }

    #[test]
    fn a_repeated_cursor_stops_the_walk() {
        let mut node = queued();
        node["estimatedTrading"]["sells"] = page(&["XMPA"], Some("DUMMYCURSOR051"));
        let mut calls = 0;
        follow_estimates(&mut node, |_, _| {
            calls += 1;
            Ok(page(&["XMPB"], Some("DUMMYCURSOR051")))
        })
        .unwrap();
        assert_eq!(calls, 1);
    }

    #[test]
    fn estimated_null_edges_stay_null() {
        let mut node = queued();
        node["estimatedTrading"]["sells"]["edges"] = Value::Null;
        let dto = account_dto(&node).unwrap();
        assert!(dto["estimated"]["sells"].is_null());
        assert_eq!(dto["estimated"]["buys"][0]["symbol"], "XMPB");
    }
}
