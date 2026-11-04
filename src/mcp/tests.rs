//! The `m1f mcp` tools, offline: every tool runs in process against the
//! synthetic fixtures through the `Source` seam, mapped by the commands' own
//! mappers, and cli-common's conformance helper checks the definitions and
//! every result's shape and size.

use std::sync::Mutex;

use pk_cli_core::CliError;
use pk_cli_documents::Document;
use pk_cli_mcp::conformance::{assert_conforms, assert_fits, call, definition_size};
use pk_cli_mcp::CallToolResult;
use serde_json::{json, Value};

use super::*;

/// A captured response's `data`, as `M1Client::execute` returns it.
fn fixture(raw: &str) -> Value {
    let v: Value = serde_json::from_str(raw).expect("fixture parses");
    v["data"].clone()
}

const TAXABLE: &str = "acct-000000001";
const ROTH: &str = "acct-000000002";

struct Fixtures {
    accounts: Vec<Value>,
    balances: Value,
    holdings: Vec<Value>,
    activity: Vec<Value>,
    documents: Vec<Document>,
    lots: Vec<Value>,
    /// Report every walk as stopped by the page ceiling.
    capped: bool,
    /// Every source call, as `method:arg`.
    calls: Mutex<Vec<String>>,
    /// When set, every call fails with this.
    fail: Mutex<Option<CliError>>,
}

impl Fixtures {
    fn new() -> Self {
        let accounts = fixture(include_str!("../../tests/fixtures/reads/accounts.json"));
        let net_worth = fixture(include_str!("../../tests/fixtures/reads/net-worth.json"));
        let holdings = fixture(include_str!("../../tests/fixtures/reads/holdings.json"));
        let activity = fixture(include_str!("../../tests/fixtures/reads/activity.json"));
        let documents = fixture(include_str!("../../tests/fixtures/reads/documents.json"));
        let lots = fixture(include_str!("../../tests/fixtures/reads/lots.json"));
        Self {
            accounts: parse::nodes(&accounts, &["viewer", "accounts"]).unwrap(),
            balances: parse::at(&net_worth, &["viewer", "overview", "balances"])
                .unwrap()
                .clone(),
            holdings: parse::nodes(&holdings, &["node", "balance", "investments", "positions"])
                .unwrap(),
            activity: parse::nodes(&activity, &["node", "investActivity", "activity"])
                .unwrap()
                .iter()
                .map(|n| activity::activity_dto(n).unwrap())
                .collect(),
            documents: parse::nodes(&documents, &["viewer", "documents"])
                .unwrap()
                .iter()
                .map(|n| documents::document_of(n).unwrap().listed())
                .collect(),
            // The live read asks for CLOSED lots only.
            lots: parse::nodes(&lots, &["node", "taxLots"])
                .unwrap()
                .iter()
                .map(|n| lots::lot_dto(n).unwrap())
                .filter(|l| l.get("closed").is_some())
                .collect(),
            capped: false,
            calls: Mutex::new(Vec::new()),
            fail: Mutex::new(None),
        }
    }

    fn record(&self, call: String) -> Result<(), CliError> {
        self.calls.lock().unwrap().push(call);
        match self.fail.lock().unwrap().as_ref() {
            None => Ok(()),
            Some(CliError::Auth(m)) => Err(CliError::Auth(m.clone())),
            Some(CliError::Upstream(m)) => Err(CliError::Upstream(m.clone())),
            Some(other) => Err(CliError::Other(other.to_string())),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl Source for Fixtures {
    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        self.record("accounts".into())?;
        Ok(self.accounts.clone())
    }

    async fn balances(&self) -> Result<Value, CliError> {
        self.record("balances".into())?;
        Ok(self.balances.clone())
    }

    /// The holdings fixture is the taxable account's; the others hold nothing.
    async fn holdings(&self, account_id: &str) -> Result<Vec<Value>, CliError> {
        self.record(format!("holdings:{account_id}"))?;
        Ok(if account_id == TAXABLE {
            self.holdings.clone()
        } else {
            Vec::new()
        })
    }

    async fn activity(
        &self,
        account_id: &str,
        since: &str,
    ) -> Result<(Vec<Value>, bool), CliError> {
        self.record(format!("activity:{account_id}:{since}"))?;
        let rows = if account_id == TAXABLE {
            self.activity.clone()
        } else {
            Vec::new()
        };
        Ok((rows, self.capped))
    }

    async fn documents(
        &self,
        types: &[&str],
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Vec<Document>, CliError> {
        self.record(format!("documents:{}", types.join(",")))?;
        let mut docs: Vec<Document> = self
            .documents
            .iter()
            .filter(|d| d.category.as_deref().is_some_and(|c| types.contains(&c)))
            .filter(|d| {
                let date = d.date.as_deref().unwrap_or_default();
                since.is_none_or(|s| date >= s) && until.is_none_or(|u| date <= u)
            })
            .cloned()
            .collect();
        docs.sort_by(|a, b| b.date.cmp(&a.date));
        Ok(docs)
    }

    /// The lots fixture is the taxable account's; the Roth IRA sold one lot
    /// at a gain that must never reach a taxable total by default.
    async fn closed_lots(&self, account_id: &str) -> Result<(Vec<Value>, bool), CliError> {
        self.record(format!("lots:{account_id}"))?;
        let rows = match account_id {
            TAXABLE => self.lots.clone(),
            ROTH => vec![json!({
                "symbol": "VXUS", "id": "lot-000000009", "quantity": "1",
                "acquired": "2024-01-02", "closed": "2026-04-01", "term": "Long",
                "cost_basis": {"amount": "50.00", "currency": "USD"},
                "realized_gain_long": {"amount": "1000.00", "currency": "USD"},
                "realized_gain": {"amount": "1000.00", "currency": "USD"}
            })],
            _ => Vec::new(),
        };
        Ok((rows, self.capped))
    }
}

fn tools() -> M1Tools<Fixtures> {
    M1Tools::new(Fixtures::new())
}

fn err(r: &CallToolResult) -> &str {
    assert!(r.is_error(), "expected an error, got {}", r.text());
    assert!(r.structured().is_none());
    r.text()
}

fn field(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i[key].as_str().unwrap_or("-").to_string())
        .collect()
}

// ---- the definitions --------------------------------------------------------

#[test]
fn the_tools_conform_to_the_mcp_profile() {
    assert_conforms(&tools());
}

#[test]
fn the_definitions_stay_small() {
    let t = tools();
    let mut total = 0;
    for name in [PORTFOLIO_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL, GAINS_TOOL] {
        let size = definition_size(&t, name);
        eprintln!("{name}: {size} characters");
        assert!(size < 2_500, "{name} takes {size} characters");
        total += size;
    }
    assert!(total <= 8_000, "the definitions take {total} characters");
}

#[test]
fn listing_and_describing_the_tools_reads_nothing() {
    let t = tools();
    let _ = t.tools();
    let _ = t.server();
    assert!(t.source().calls().is_empty());
}

// ---- m1_portfolio -----------------------------------------------------------

#[test]
fn the_portfolio_is_net_worth_account_totals_and_positions() {
    let t = tools();
    let r = call(&t, PORTFOLIO_TOOL, json!({}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    assert_eq!(out["net_worth"]["total"], "12345.67");
    assert_eq!(out["net_worth"]["liabilities"], "654.33");
    assert!(out["net_worth"].get("partial").is_none());
    let names = field(&out["accounts"], "name");
    assert!(names.contains(&"Fun Money".to_string()), "{names:?}");
    assert!(names.contains(&"Roth IRA".to_string()), "{names:?}");
    assert!(names.contains(&"Earn".to_string()), "{names:?}");
    assert!(out["accounts"][0].get("account_id").is_none(), "concise");

    assert_eq!(field(&out["items"], "symbol"), ["VTI", "VUG"]);
    let vti = &out["items"][0];
    assert_eq!(vti["account"], "Fun Money");
    assert_eq!(vti["market_value"], "1250.75");
    assert_eq!(vti["cost_basis"], "1200.50");
    assert_eq!(vti["unrealized_gain"], "50.25");
    assert!(
        vti.get("name").is_none(),
        "concise leaves out the security name"
    );
    assert_eq!(out["returned"], 2);
    assert!(out.get("next_cursor").is_none());
    // One holdings read per account, after the accounts and the rollup.
    let calls = t.source().calls();
    assert_eq!(
        calls,
        [
            "accounts",
            "balances",
            "holdings:acct-000000001",
            "holdings:acct-000000002",
            "holdings:acct-000000003"
        ]
    );
}

#[test]
fn detailed_positions_add_names_prices_and_ids() {
    let t = tools();
    let r = call(&t, PORTFOLIO_TOOL, json!({"response_format": "detailed"}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    assert_eq!(out["items"][0]["name"], "Vanguard Total Stock Market ETF");
    assert_eq!(out["items"][0]["average_price"], "371.41");
    let ids: Vec<&Value> = out["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a.get("account_id"))
        .collect();
    assert!(!ids.is_empty());
}

#[test]
fn an_account_is_named_not_numbered() {
    let t = tools();
    let r = call(
        &t,
        PORTFOLIO_TOOL,
        json!({"account": "fun money", "symbol": "vug"}),
    );
    let out = assert_fits(&t, PORTFOLIO_TOOL, &r);
    assert_eq!(field(&out["items"], "symbol"), ["VUG"]);
    let calls = t.source().calls();
    assert_eq!(
        calls.last().map(String::as_str),
        Some("holdings:acct-000000001")
    );
    assert!(!calls.contains(&"holdings:acct-000000002".to_string()));
}

#[test]
fn an_unknown_account_lists_the_names_that_exist() {
    let t = tools();
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({"account": "Rainy Day"}))).to_string();
    assert!(text.starts_with("not_found:"), "{text}");
    assert!(text.contains("Fun Money, Roth IRA"), "{text}");
}

#[test]
fn positions_page_with_a_cursor_bound_to_the_filters() {
    let t = tools();
    let first = call(&t, PORTFOLIO_TOOL, json!({"limit": 1}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &first);
    assert_eq!(field(&out["items"], "symbol"), ["VTI"]);
    let cursor = out["next_cursor"].as_str().unwrap().to_string();

    let second = call(&t, PORTFOLIO_TOOL, json!({"limit": 1, "cursor": cursor}));
    let out = assert_fits(&t, PORTFOLIO_TOOL, &second);
    assert_eq!(field(&out["items"], "symbol"), ["VUG"]);
    assert!(out.get("next_cursor").is_none());

    let other = call(
        &t,
        PORTFOLIO_TOOL,
        json!({"limit": 1, "cursor": cursor, "symbol": "VTI"}),
    );
    assert!(err(&other).starts_with("usage:"));
}

// ---- m1_activity ------------------------------------------------------------

#[test]
fn activity_is_newest_first_with_names_and_signed_amounts() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-07-01", "until": "2026-08-31"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["since"], "2026-07-01");
    assert_eq!(out["complete"], true);
    let dates = field(&out["items"], "date");
    assert_eq!(dates[0], "2026-08-13");
    assert!(dates.windows(2).all(|w| w[0] >= w[1]), "{dates:?}");
    let withdrawal = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["description"] == "Withdrawal completed.")
        .unwrap();
    assert_eq!(withdrawal["amount"], "-25.00");
    assert_eq!(withdrawal["account"], "Fun Money");
    assert!(withdrawal.get("id").is_none(), "concise");
    // Every account was read from `since`.
    assert!(t
        .source()
        .calls()
        .contains(&"activity:acct-000000003:2026-07-01".to_string()));
}

/// A page boundary falls inside a day, and a row posts before the next page. A cursor holds no
/// state at M1, so a second set of fixtures stands for the later read.
#[test]
fn an_activity_row_that_posts_between_pages_repeats_nothing_and_skips_nothing() {
    let template = Fixtures::new().activity[0].clone();
    let row = |id: &str, date: &str| {
        let mut row = template.clone();
        row["id"] = json!(id);
        row["date"] = json!(date);
        row
    };
    let with_rows = |rows: Vec<Value>| {
        let mut fixtures = Fixtures::new();
        fixtures.activity = rows;
        M1Tools::new(fixtures)
    };
    let before = vec![
        row("d", "2026-03-04"),
        row("c", "2026-03-03"),
        row("b", "2026-03-03"),
        row("a", "2026-03-01"),
    ];
    let mut after = vec![row("e", "2026-03-05")];
    after.extend(before.clone());
    let args = json!({"since": "2026-01-01", "until": "2026-12-31", "limit": 2,
                      "response_format": "detailed"});
    let ids = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap().to_string())
            .collect()
    };

    let tools = with_rows(before);
    let answer = call(&tools, ACTIVITY_TOOL, args.clone());
    let first = assert_fits(&tools, ACTIVITY_TOOL, &answer);
    let mut seen = ids(first);
    assert_eq!(seen[0], "d");
    let later = with_rows(after);
    let mut cursor = first["next_cursor"].clone();
    while cursor.is_string() {
        let mut next = args.clone();
        next["cursor"] = cursor;
        let answer = call(&later, ACTIVITY_TOOL, next);
        let page = assert_fits(&later, ACTIVITY_TOOL, &answer);
        seen.extend(ids(page));
        cursor = page["next_cursor"].clone();
    }
    let mut sorted = seen.clone();
    sorted.sort();
    assert_eq!(sorted, ["a", "b", "c", "d"], "{seen:?}");
}

#[test]
fn activity_narrows_by_window_type_and_symbol() {
    let t = tools();
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-08-01", "until": "2026-08-31", "type": "trade"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "symbol"), ["VTI"]);
    assert_eq!(out["items"][0]["amount"], "465.00");

    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-07-01", "until": "2026-07-31", "symbol": "VUG"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "type"), ["Position"]);

    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-08-01", "until": "2026-08-10"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(field(&out["items"], "date"), ["2026-08-06"]);
}

#[test]
fn activity_defaults_to_the_year_to_date() {
    let t = tools();
    let r = call(&t, ACTIVITY_TOOL, json!({"until": "2026-08-31"}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["since"], "2026-01-01");
    let today = dates::fmt_iso(dates::today());
    let r = call(&t, ACTIVITY_TOOL, json!({}));
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["until"], today);
    assert_eq!(out["since"], format!("{}-01-01", &today[..4]));
}

#[test]
fn a_capped_walk_says_the_history_is_incomplete() {
    let mut fixtures = Fixtures::new();
    fixtures.capped = true;
    let t = M1Tools::new(fixtures);
    let r = call(
        &t,
        ACTIVITY_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, ACTIVITY_TOOL, &r);
    assert_eq!(out["complete"], false);
    let r = call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    assert_eq!(out["complete"], false);
}

#[test]
fn bad_dates_fail_before_any_read() {
    let t = tools();
    for args in [
        json!({"since": "08/01/2026"}),
        json!({"until": "2026-13-01"}),
        json!({"since": "2026-09-01", "until": "2026-08-01"}),
    ] {
        let text = err(&call(&t, ACTIVITY_TOOL, args.clone())).to_string();
        assert!(text.starts_with("usage:"), "{args}: {text}");
    }
    let text = err(&call(&t, GAINS_TOOL, json!({"since": "2026-1-x"}))).to_string();
    assert!(text.contains("YYYY-MM-DD"), "{text}");
    let text = err(&call(
        &t,
        DOCUMENTS_TOOL,
        json!({"since": "2026-09-01", "until": "2026-08-01"}),
    ))
    .to_string();
    assert!(text.starts_with("usage:"), "{text}");
    assert!(t.source().calls().is_empty());
}

/// An unpadded date compares as a string, so it is padded first:
/// `"2026-8-5" < "2026-08-01"` as text, though 5 August is later.
#[test]
fn unpadded_dates_are_padded_before_any_comparison() {
    let (s, u) = window(Some("2026-8-5"), Some("2026-08-31")).unwrap();
    assert_eq!((s.as_str(), u.as_str()), ("2026-08-05", "2026-08-31"));
    let (s, _) = window(None, Some("2026-3-1")).unwrap();
    assert_eq!(s, "2026-01-01");
}

// ---- m1_documents -----------------------------------------------------------

#[test]
fn documents_list_names_and_types_never_a_link() {
    let t = tools();
    let r = call(&t, DOCUMENTS_TOOL, json!({}));
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    let dates = field(&out["items"], "date");
    assert!(dates.windows(2).all(|w| w[0] >= w[1]), "{dates:?}");
    let types = field(&out["items"], "type");
    assert!(types.contains(&"tax-form".to_string()), "{types:?}");
    assert!(types.contains(&"statement".to_string()), "{types:?}");
    assert!(out["items"][0].get("id").is_none(), "concise");
    let text = r.text();
    assert!(!text.contains("http"), "{text}");
    assert_eq!(
        t.source().calls(),
        ["documents:STATEMENT,TAX_FORM,TRADE_CONFIRMATION,INVESTMENTS_RELATED,ACCOUNT_DOCUMENT"]
    );
}

#[test]
fn tax_forms_alone_with_their_ids_on_request() {
    let t = tools();
    let r = call(
        &t,
        DOCUMENTS_TOOL,
        json!({"type": "tax-form", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert_eq!(field(&out["items"], "type"), ["tax-form"]);
    assert_eq!(out["items"][0]["id"], "doc-000000001");
    assert!(out["items"][0]["name"]
        .as_str()
        .unwrap()
        .starts_with("Tax Form 1099"));
    assert_eq!(t.source().calls(), ["documents:TAX_FORM"]);
}

#[test]
fn an_unknown_document_type_names_the_known_ones() {
    let t = tools();
    let text = err(&call(&t, DOCUMENTS_TOOL, json!({"type": "1099"}))).to_string();
    assert!(text.starts_with("usage:"), "{text}");
    assert!(text.contains("tax-form"), "{text}");
    assert!(t.source().calls().is_empty());
}

/// If M1 ever changes its id blob so it no longer decodes, the id (and a
/// name that fell back to it) would be the blob, which can embed the account
/// number and a signed link. Neither reaches a result.
#[test]
fn an_undecodable_id_blob_never_reaches_a_result() {
    let blob = "SW52ZXN0QWNjb3VudERvY3VtZW50OnsiZG9jdW1lbnQiOm51bGwsInVybCI6Imh0dHBzOi8v".repeat(2);
    let node = json!({"id": blob, "date": "2026-02-01", "type": "TAX_FORM"});
    let mut fixtures = Fixtures::new();
    fixtures
        .documents
        .push(documents::document_of(&node).unwrap().listed());
    let t = M1Tools::new(fixtures);
    let r = call(
        &t,
        DOCUMENTS_TOOL,
        json!({"type": "tax-form", "response_format": "detailed"}),
    );
    let out = assert_fits(&t, DOCUMENTS_TOOL, &r);
    assert!(!r.text().contains(&blob), "{}", r.text());
    let undecoded = out["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["date"] == "2026-02-01")
        .unwrap();
    assert!(undecoded.get("id").is_none(), "{undecoded}");
    assert_eq!(undecoded["name"], "Untitled document");
}

// ---- m1_realized_gains ------------------------------------------------------

#[test]
fn realized_gains_total_exactly_over_taxable_accounts() {
    let t = tools();
    let r = call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    let totals = &out["totals"];
    assert_eq!(totals["short_term"], "-12.75");
    assert_eq!(totals["long_term"], "45.50");
    assert_eq!(totals["total"], "32.75");
    assert_eq!(totals["disallowed_wash_sale"], "12.75");
    assert_eq!(totals["lots"], 2);
    assert_eq!(out["complete"], true);
    // Newest sale first; the wash sale shows its disallowed loss.
    assert_eq!(field(&out["items"], "symbol"), ["VB", "VUG"]);
    assert_eq!(out["items"][0]["disallowed_wash_sale"], "12.75");
    assert!(out["items"][1].get("disallowed_wash_sale").is_none());
    assert_eq!(out["items"][1]["gain"], "45.50");
    assert_eq!(out["items"][1]["account"], "Fun Money");
    // The Roth IRA is not read unless named.
    let calls = t.source().calls();
    assert!(!calls.contains(&format!("lots:{ROTH}")), "{calls:?}");
    assert!(
        calls.contains(&"lots:acct-000000003".to_string()),
        "{calls:?}"
    );
}

#[test]
fn naming_a_retirement_account_reads_it_alone() {
    let t = tools();
    let r = call(
        &t,
        GAINS_TOOL,
        json!({"account": "Roth IRA", "since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    assert_eq!(out["totals"]["total"], "1000.00");
    assert_eq!(field(&out["items"], "symbol"), ["VXUS"]);
    assert_eq!(t.source().calls(), ["accounts", "lots:acct-000000002"]);
}

#[test]
fn the_sale_window_and_symbol_narrow_the_totals_too() {
    let t = tools();
    let r = call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-06-10", "until": "2026-06-30"}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    assert_eq!(out["totals"]["total"], "-12.75");
    assert_eq!(out["totals"]["lots"], 1);

    let r = call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "symbol": "vug"}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    assert_eq!(out["totals"]["total"], "45.50");
}

/// The totals cover every matching lot, not just the page returned.
#[test]
fn the_totals_do_not_shrink_with_the_page() {
    let t = tools();
    let r = call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31", "limit": 1}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    assert_eq!(out["returned"], 1);
    assert_eq!(out["totals"]["lots"], 2);
    assert_eq!(out["totals"]["total"], "32.75");
    assert!(out["next_cursor"].is_string());
}

/// A gain belongs to the year of its sale, so a closed lot M1 sent without
/// one is in no total, whatever the window, and is counted apart.
#[test]
fn a_closed_lot_without_a_sale_date_is_in_no_total() {
    let mut fixtures = Fixtures::new();
    fixtures.lots.push(json!({
        "symbol": "VT", "id": "lot-000000010", "acquired": "2026-02-02", "term": "Short",
        "realized_gain_short": {"amount": "99.00", "currency": "USD"},
        "realized_gain": {"amount": "99.00", "currency": "USD"}
    }));
    let t = M1Tools::new(fixtures);
    let r = call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    );
    let out = assert_fits(&t, GAINS_TOOL, &r);
    assert_eq!(out["totals"]["total"], "32.75");
    assert_eq!(out["totals"]["lots"], 2);
    assert_eq!(out["totals"]["undated"], 1);
    assert!(!field(&out["items"], "symbol").contains(&"VT".to_string()));
}

/// An amount that is not a decimal fails the call: a total that dropped or
/// zeroed a lot would be a wrong tax figure.
#[test]
fn a_lot_amount_that_is_not_a_decimal_fails_the_totals() {
    let mut fixtures = Fixtures::new();
    fixtures.lots.push(json!({
        "symbol": "VT", "id": "lot-000000011", "closed": "2026-03-03", "term": "Short",
        "realized_gain": {"amount": "12,50", "currency": "USD"}
    }));
    let t = M1Tools::new(fixtures);
    let text = err(&call(
        &t,
        GAINS_TOOL,
        json!({"since": "2026-01-01", "until": "2026-12-31"}),
    ))
    .to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(text.contains("12,50"), "{text}");
}

// ---- errors -----------------------------------------------------------------

#[test]
fn a_missing_session_asks_for_the_browser_login_in_a_terminal() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Auth(
        "not logged in — run `m1f auth login --browser`".into(),
    ));
    for name in [PORTFOLIO_TOOL, ACTIVITY_TOOL, DOCUMENTS_TOOL, GAINS_TOOL] {
        let text = err(&call(&t, name, json!({}))).to_string();
        assert!(text.starts_with("auth:"), "{name}: {text}");
        assert!(
            text.contains(
                "Ask the user to run `m1f auth login --browser --overwrite` in a terminal"
            ),
            "{name}: {text}"
        );
        assert!(text.contains("never sign in"), "{name}: {text}");
    }
}

/// A block at the edge is not cleared by signing in, so the fix does not lead with one.
#[test]
fn a_block_at_the_edge_does_not_ask_for_a_new_sign_in_first() {
    let t = tools();
    const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
    for blocked in [
        crate::client::tests::read_answer(403, PAGE).unwrap_err(),
        crate::client::tests::read_answer(403, "Forbidden").unwrap_err(),
        crate::auth0::tests::blocked_token_answer(),
    ] {
        *t.source().fail.lock().unwrap() = Some(blocked);
        let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
        assert!(text.starts_with("upstream:"), "{text}");
        assert!(
            text.contains("Wait or try another network, then call the tool again once"),
            "{text}"
        );
        assert!(text.contains("Only if it still fails after that"), "{text}");
        assert!(text.contains("never sign in"), "{text}");
        assert!(!text.contains("in a terminal, then call"), "{text}");
    }
}

/// A read refused with a 401 still asks for the sign-in.
#[test]
fn an_html_401_asks_for_the_sign_in() {
    let t = tools();
    const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
    *t.source().fail.lock().unwrap() =
        Some(crate::client::tests::read_answer(401, PAGE).unwrap_err());
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("auth:"), "{text}");
    assert!(
        text.contains("Ask the user to run `m1f auth login --browser --overwrite` in a terminal"),
        "{text}"
    );
}

#[test]
fn a_provider_failure_is_upstream_not_the_arguments() {
    let t = tools();
    *t.source().fail.lock().unwrap() = Some(CliError::Upstream("HTTP 503".into()));
    let text = err(&call(&t, PORTFOLIO_TOOL, json!({}))).to_string();
    assert!(text.starts_with("upstream:"), "{text}");
    assert!(!text.contains("auth login"), "{text}");
}

#[test]
fn the_instructions_name_the_browser_login_and_read_only_access() {
    let text = pk_cli_mcp::instructions(&tools());
    assert!(text.contains("`m1f auth login --browser`"), "{text}");
    assert!(text.contains("read-only"), "{text}");
}
