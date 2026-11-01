//! `m1f transactions list` — the FDX normalized transaction ledger for one
//! account.
//!
//! The richest, most tax-friendly transaction surface M1 exposes
//! (`Account.fdxTransactions`), in the industry-standard Financial Data
//! Exchange format. Distinct from `activity list` (M1's own activity view) and
//! `transfers list` (cash in/out): this is the per-transaction ledger with a
//! normalized type, debit/credit direction, per-security detail, and
//! commission/fees — the cleanest input for basis and aggregation work.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{done_paging, emit, items, note_empty, paginate, table_view, Ctx};
use crate::{graphql, parse};

const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    range.validate()?;
    let account = ctx.account()?;

    let page_size = range.limit.map(|n| n.min(PAGE_SIZE)).unwrap_or(PAGE_SIZE);
    let mut cursor: Option<String> = None;
    let mut rows: Vec<Value> = Vec::new();
    let mut pages = 0usize;
    let mut truncated = false;

    const PATH: &[&str] = &["node", "fdxTransactions"];
    loop {
        let vars = json!({ "accountId": account, "first": page_size, "after": cursor });
        let data = ctx.read(|c| {
            c.execute(
                graphql::TRANSACTIONS,
                vars.clone(),
                Some("AccountTransactions"),
            )
        })?;
        parse::require_node(&data)?;
        let container = parse::at(&data, PATH)?.clone();
        for node in parse::nodes(&data, PATH)? {
            rows.push(transaction_dto(&node)?);
        }
        pages += 1;

        let next = parse::next_cursor(&container);
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
    if truncated && !ctx.common.quiet {
        eprintln!("stopped after {MAX_PAGES} pages — narrow with --since/--until or --limit");
    }

    let rows = paginate(rows, "date", range);
    if rows.is_empty() {
        note_empty(ctx, "transactions");
    }
    emit(
        ctx,
        "transaction-list",
        json!({ "items": rows, "truncated": truncated }),
        |v| {
            output::table(&table_view(
                &items(v, "items"),
                &["date", "type", "symbol", "units", "amount", "status"],
            ));
        },
    );
    Ok(())
}

fn transaction_dto(v: &Value) -> Result<Value, CliError> {
    let mut dto = json!({ "id": parse::id(v, "id")? });
    // FDX timestamps are RFC 3339; `transactionTimestamp` is the trade/effective
    // date (what tax work keys on), `postedTimestamp` the settle date.
    if let Some(date) = parse::date_at(v, &["transactionTimestamp", "postedTimestamp", "date"]) {
        dto["date"] = json!(date);
    }
    // The normalized FDX type (PURCHASED / SOLD / DIVIDEND / DEPOSIT / …). The
    // two variants alias it differently (`investmentType` / `depositType`)
    // because their enums conflict — see graphql.rs. Fall back to a readable
    // form of `__typename` for a variant that carries neither.
    if let Some(kind) = parse::opt_string(v, "investmentType")
        .or_else(|| parse::opt_string(v, "depositType"))
        .or_else(|| parse::opt_string(v, "transactionType"))
        .or_else(|| {
            parse::opt_string(v, "__typename").map(|t| {
                t.strip_prefix("Fdx")
                    .and_then(|s| s.strip_suffix("Transaction"))
                    .unwrap_or(&t)
                    .to_string()
            })
        })
    {
        dto["type"] = json!(kind);
    }
    if let Some(symbol) = parse::opt_string(v, "symbol") {
        dto["symbol"] = json!(symbol);
    }
    // Share count: fractional, a plain string decimal, never money.
    if let Some(units) = parse::decimal_string(v, "units") {
        dto["units"] = json!(units);
    }
    if let Some(price) = parse::money_at(v, "unitPrice") {
        dto["unit_price"] = serde_json::to_value(price).unwrap_or(Value::Null);
    }
    if let Some(desc) = parse::opt_string(v, "description") {
        dto["description"] = json!(desc);
    }
    if let Some(payee) = parse::opt_string(v, "payee") {
        dto["payee"] = json!(payee);
    }
    if let Some(amount) = parse::money_at(v, "amount") {
        dto["amount"] = serde_json::to_value(amount).unwrap_or(Value::Null);
    }
    // `debitCreditMemo` (DEBIT / CREDIT / MEMO) is the money direction — the
    // sign FDX carries out of band rather than in `amount`.
    if let Some(dir) = parse::opt_string(v, "debitCreditMemo") {
        dto["direction"] = json!(dir);
    }
    if let Some(status) = parse::opt_string(v, "status") {
        dto["status"] = json!(status);
    }
    if let Some(commission) = parse::money_at(v, "commission") {
        dto["commission"] = serde_json::to_value(commission).unwrap_or(Value::Null);
    }
    if let Some(fees) = parse::money_at(v, "fees") {
        dto["fees"] = serde_json::to_value(fees).unwrap_or(Value::Null);
    }
    if let Some(cat) = parse::opt_string(v, "category") {
        dto["category"] = json!(cat);
    }
    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_dto_maps_an_investment_buy() {
        let v = json!({
            "__typename": "FdxInvestmentTransaction",
            "id": "t1",
            "amount": 203.8,
            "description": "0.53118 shares of VTI purchased.",
            "transactionTimestamp": "2026-08-13T13:46:53.94176Z",
            "status": "POSTED",
            "debitCreditMemo": "DEBIT",
            "symbol": "VTI",
            "units": 0.53118,
            "unitPrice": 383.67,
            "investmentType": "PURCHASED",
            "commission": null,
            "fees": 0
        });
        let dto = transaction_dto(&v).unwrap();
        assert_eq!(dto["date"], json!("2026-08-13"));
        assert_eq!(dto["type"], json!("PURCHASED"));
        assert_eq!(dto["symbol"], json!("VTI"));
        assert_eq!(dto["units"], json!("0.53118"));
        assert_eq!(dto["unit_price"]["amount"], json!("383.67"));
        assert_eq!(dto["amount"]["amount"], json!("203.80"));
        assert_eq!(dto["direction"], json!("DEBIT"));
        assert_eq!(dto["status"], json!("POSTED"));
        assert_eq!(dto["fees"]["amount"], json!("0.00"));
        // A null commission is omitted, not rendered as $0.
        assert!(dto.get("commission").is_none());
    }

    #[test]
    fn transaction_dto_maps_a_deposit_with_payee() {
        let v = json!({
            "__typename": "FdxDepositTransaction",
            "id": "t2", "amount": 500.0, "depositType": "DEPOSIT",
            "payee": "External Bank", "status": "POSTED", "debitCreditMemo": "CREDIT",
            "transactionTimestamp": "2026-08-01T00:00:00Z"
        });
        let dto = transaction_dto(&v).unwrap();
        assert_eq!(dto["type"], json!("DEPOSIT"));
        assert_eq!(dto["payee"], json!("External Bank"));
        assert_eq!(dto["direction"], json!("CREDIT"));
        assert!(dto.get("symbol").is_none());
    }

    #[test]
    fn an_unknown_variant_falls_back_to_a_readable_typename() {
        let dto = transaction_dto(&json!({
            "__typename": "FdxLoanTransaction", "id": "t3", "amount": 10.0
        }))
        .unwrap();
        assert_eq!(dto["type"], json!("Loan"));
    }

    #[test]
    fn a_missing_id_fails_loudly() {
        assert_eq!(
            transaction_dto(&json!({ "amount": 1.0 }))
                .unwrap_err()
                .exit_code(),
            5
        );
    }
}
