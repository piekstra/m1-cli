//! Contract tests over the fixtures in `tests/fixtures/`.
//!
//! These assert the exact fields the table views and DTO builders read, so an
//! upstream rename fails loudly here instead of silently emptying a column in
//! someone's portfolio listing.
//!
//! Plus the scrubbing-policy test, which is deliberately written as "every
//! identity-bearing value matches a known dummy shape" rather than as a
//! denylist of real values — a denylist would have to name what it exists to
//! exclude.

use std::path::PathBuf;

use serde_json::Value;

fn fixture(rel: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel);
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {rel}: {e}"));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parsing {rel}: {e}"))
}

/// Walk every string in a JSON document, with a dotted path for diagnostics.
fn walk(v: &Value, path: &str, f: &mut impl FnMut(&str, &str)) {
    match v {
        Value::String(s) => f(path, s),
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk(item, &format!("{path}[{i}]"), f);
            }
        }
        Value::Object(map) => {
            for (k, child) in map {
                let p = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                walk(child, &p, f);
            }
        }
        _ => {}
    }
}

fn all_fixtures() -> Vec<(&'static str, Value)> {
    vec![
        (
            "auth/authenticate-success.json",
            fixture("auth/authenticate-success.json"),
        ),
        (
            "auth/authenticate-failure.json",
            fixture("auth/authenticate-failure.json"),
        ),
        (
            "auth/authenticate-mfa.json",
            fixture("auth/authenticate-mfa.json"),
        ),
        (
            "auth/auth0-spa-cache.json",
            fixture("auth/auth0-spa-cache.json"),
        ),
        (
            "reads/viewer-is-authenticated.json",
            fixture("reads/viewer-is-authenticated.json"),
        ),
        (
            "errors/unauthenticated.json",
            fixture("errors/unauthenticated.json"),
        ),
        (
            "errors/validation-failed.json",
            fixture("errors/validation-failed.json"),
        ),
        ("reads/accounts.json", fixture("reads/accounts.json")),
        ("reads/holdings.json", fixture("reads/holdings.json")),
        ("reads/activity.json", fixture("reads/activity.json")),
        ("reads/dividends.json", fixture("reads/dividends.json")),
        ("reads/documents.json", fixture("reads/documents.json")),
        ("reads/lots.json", fixture("reads/lots.json")),
        (
            "reads/system-status.json",
            fixture("reads/system-status.json"),
        ),
        ("reads/net-worth.json", fixture("reads/net-worth.json")),
        ("reads/transfers.json", fixture("reads/transfers.json")),
        (
            "reads/transactions.json",
            fixture("reads/transactions.json"),
        ),
        ("reads/ira.json", fixture("reads/ira.json")),
        ("reads/summary.json", fixture("reads/summary.json")),
    ]
}

// ---------------------------------------------------------------------------
// Scrubbing policy
// ---------------------------------------------------------------------------

fn is_dummy_id(s: &str) -> bool {
    let Some((prefix, digits)) = s.split_once('-') else {
        return false;
    };
    matches!(prefix, "acct" | "hold" | "act" | "doc")
        && digits.len() == 9
        && digits.chars().all(|c| c.is_ascii_digit())
}

/// URL-shaped values that identify rather than locate (see the URL rule).
const PUBLIC_IDENTIFIERS: &[&str] = &["https://lens.m1finance.com"];

#[test]
fn fixtures_obey_the_scrubbing_policy() {
    for (name, doc) in all_fixtures() {
        walk(&doc, "", &mut |path, s| {
            let leaf = path.rsplit('.').next().unwrap_or(path);
            let leaf = leaf.split('[').next().unwrap_or(leaf);

            // Tokens must be the known dummies — never a real JWT.
            if leaf.ends_with("Token") || leaf.ends_with("token") {
                assert!(
                    s.starts_with("DUMMY."),
                    "{name}: token at `{path}` is not a DUMMY. value"
                );
            }

            // Ids must match the documented dummy shape.
            if leaf == "id" {
                assert!(
                    is_dummy_id(s),
                    "{name}: id at `{path}` (`{s}`) is not a <prefix>-######### dummy"
                );
            }

            // Cursors must be the documented dummy shape.
            if leaf.ends_with("Cursor") {
                assert!(
                    s.starts_with("DUMMYCURSOR"),
                    "{name}: cursor at `{path}` is not a DUMMYCURSOR value"
                );
            }

            // Any URL must be unresolvable. A pre-signed URL is a live
            // credential; `example.invalid` cannot resolve by RFC 2606.
            // The one exception is an identifier that is URL-shaped but
            // names no resource: the Auth0 API audience, printed in M1's web
            // bundle, which the browser-session reader checks a capture
            // against.
            if (s.starts_with("http://") || s.starts_with("https://"))
                && !PUBLIC_IDENTIFIERS.contains(&s)
            {
                assert!(
                    s.contains("example.invalid"),
                    "{name}: URL at `{path}` is not on example.invalid"
                );
            }

            // No email addresses anywhere.
            assert!(
                !s.contains('@'),
                "{name}: value at `{path}` looks like an email address"
            );

            // No bare long digit runs, which is what a real account number,
            // SSN, or card number looks like. Dummy ids are exempt because
            // they carry a prefix and were checked above.
            let longest_digit_run = s
                .split(|c: char| !c.is_ascii_digit())
                .map(str::len)
                .max()
                .unwrap_or(0);
            assert!(
                longest_digit_run <= 8 || is_dummy_id(s),
                "{name}: value at `{path}` has a {longest_digit_run}-digit run — \
                 that shape is what a real account number looks like"
            );
        });
    }
}

#[test]
fn no_fixture_carries_a_real_looking_jwt() {
    // A JWT is three base64 segments; ours are the DUMMY placeholders. This
    // catches a real token pasted in with the right field name but the wrong
    // assumption that "it's expired, so it's fine".
    for (name, doc) in all_fixtures() {
        walk(&doc, "", &mut |path, s| {
            let segments: Vec<&str> = s.split('.').collect();
            let looks_like_jwt = segments.len() == 3
                && segments[0].starts_with("eyJ")
                && segments.iter().all(|seg| seg.len() > 8);
            assert!(!looks_like_jwt, "{name}: `{path}` looks like a real JWT");
        });
    }
}

// ---------------------------------------------------------------------------
// Shape contracts — the fields the code actually reads
// ---------------------------------------------------------------------------

/// The single most important contract on this API: failure arrives as HTTP 200
/// with a populated `errors` array, so the array is what decides success.
#[test]
fn error_envelopes_carry_the_array_and_code_the_classifier_reads() {
    let unauth = fixture("errors/unauthenticated.json");
    let errors = unauth["errors"].as_array().expect("errors array");
    assert!(!errors.is_empty());
    assert_eq!(errors[0]["extensions"]["code"], "UNAUTHENTICATED");
    assert!(errors[0]["message"].is_string());
    // `data: null` alongside errors is the shape that must not render as empty.
    assert!(unauth["data"].is_null());

    // M1's real envelope (observed live): the code sits at the TOP LEVEL of
    // the error object, not under extensions, alongside an isAuthError flag.
    let invalid = fixture("errors/validation-failed.json");
    assert_eq!(invalid["errors"][0]["code"], "GRAPHQL_VALIDATION_FAILED");
    assert!(invalid["errors"][0]["isAuthError"].is_boolean());
}

/// The second trap: a failed auth has NO `errors` array at all.
#[test]
fn a_failed_authenticate_has_a_clean_envelope_and_a_false_flag() {
    let f = fixture("auth/authenticate-failure.json");
    assert!(
        f.get("errors").is_none(),
        "the whole point of this fixture is that the GraphQL envelope looks clean"
    );
    let payload = &f["data"]["authenticate"];
    assert_eq!(payload["didSucceed"], false);
    // `error` is a SCALAR on this API, not an object — a parser expecting
    // `error.message` would read null and report "no reason given".
    assert!(
        payload["error"].is_string(),
        "error must be a scalar string, got {:?}",
        payload["error"]
    );
    assert!(payload["outcome"].is_null());
}

#[test]
fn a_successful_authenticate_carries_both_tokens_where_the_extractor_looks() {
    let f = fixture("auth/authenticate-success.json");
    let payload = &f["data"]["authenticate"];
    assert_eq!(payload["didSucceed"], true);
    assert!(payload["outcome"]["accessToken"].is_string());
    assert!(payload["outcome"]["refreshToken"].is_string());
}

#[test]
fn accounts_have_the_columns_the_table_view_uses() {
    let f = fixture("reads/accounts.json");
    let conn = &f["data"]["viewer"]["accounts"];
    // Live-verified 2026-08-13: this connection DOES carry pageInfo (the
    // research had guessed it didn't), so `accounts list` follows cursors.
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    let edges = conn["edges"].as_array().expect("relay edges");
    assert!(!edges.is_empty());
    for e in edges {
        let n = &e["node"];
        assert!(n["id"].is_string(), "id feeds the identifying column");
        assert!(n["name"].is_string());
        assert!(n["registration"].is_string());
        assert!(n["status"].is_string());
        // Money lives under `balance`: totalValue is a wrapper object with a
        // hasValue flag, cash exposes `available`.
        assert!(n["balance"]["totalValue"]["hasValue"].is_boolean());
        assert!(n["balance"]["cash"]["available"].is_number());
    }
    // At least one account must exercise hasValue:false — the "M1 itself
    // can't price this" case that must render as omitted, not $0.00.
    let any_unpriced = edges
        .iter()
        .any(|e| e["node"]["balance"]["totalValue"]["hasValue"] == false);
    assert!(any_unpriced, "fixture should exercise an unpriced account");
}

#[test]
fn holdings_expose_the_security_and_the_cost_basis() {
    let f = fixture("reads/holdings.json");
    // Live-verified path: positions hang off balance.investments, not off the
    // account node directly.
    let conn = &f["data"]["node"]["balance"]["investments"]["positions"];
    assert!(conn["total"].is_number());
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    let edges = conn["edges"].as_array().expect("relay edges");
    assert!(edges.iter().all(|e| e["cursor"].is_string()));
    for e in edges {
        let n = &e["node"];
        assert!(n["id"].is_string());
        assert!(n["quantity"].is_number());
        // Cost and value are wrapper objects (schema-verified).
        assert!(
            n["cost"]["cost"].is_number(),
            "cost basis drives tax reporting"
        );
        assert!(n["value"]["value"].is_number());
        assert!(n["unrealizedGain"]["gain"].is_number());
        assert!(n["security"]["symbol"].is_string());
        assert!(n["security"]["name"].is_string());
    }
}

/// M1 trades fractional slices, so a quantity that only round-trips as an
/// integer would silently misreport a position.
#[test]
fn holdings_keep_fractional_share_precision() {
    let f = fixture("reads/holdings.json");
    let q = f["data"]["node"]["balance"]["investments"]["positions"]["edges"][0]["node"]
        ["quantity"]
        .as_f64()
        .expect("numeric quantity");
    assert!(
        q.fract() > 0.0,
        "fixture should exercise a fractional share"
    );
}

#[test]
fn activity_has_the_date_type_description_and_amount_columns() {
    let f = fixture("reads/activity.json");
    // Live-verified path: activity hangs off investActivity.
    let conn = &f["data"]["node"]["investActivity"]["activity"];
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    assert!(conn["pageInfo"]["endCursor"].is_string());
    for e in conn["edges"].as_array().expect("relay edges") {
        let n = &e["node"];
        assert!(n["id"].is_string());
        assert!(n["date"].is_string());
        // `id date title description` are interface fields, present on every
        // variant; `amount` is not (TradeSummary and Position have none).
        assert!(n["title"].is_string());
        assert!(n["description"].is_string());
        // `InvestActivityEntry` is an interface; the variant arrives as
        // __typename rather than a `type` field.
        assert!(n["__typename"].is_string());
    }
    // The fixture must exercise a Trade with its per-trade detail…
    let trade = conn["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["node"]["__typename"] == "InvestActivityTradeEntry")
        .expect("fixture should carry a Trade variant");
    assert!(trade["node"]["sharePrice"].is_number());
    assert!(trade["node"]["tradeSecurity"]["symbol"].is_string());
    // …and a TradeSummary with its aggregate counts.
    let summary = conn["edges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["node"]["__typename"] == "InvestActivityTradeSummaryEntry")
        .expect("fixture should carry a TradeSummary variant");
    assert!(summary["node"]["countOfBuys"].is_number());
}

/// Debits must stay negative through the whole pipeline; an `abs()` anywhere
/// would turn a withdrawal into a deposit.
#[test]
fn activity_includes_a_negative_amount() {
    let f = fixture("reads/activity.json");
    let any_negative = f["data"]["node"]["investActivity"]["activity"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["node"]["amount"].as_f64().unwrap_or(0.0) < 0.0);
    assert!(any_negative, "fixture should exercise a debit");
}

#[test]
fn documents_carry_the_profile_fields_and_a_separate_url() {
    let f = fixture("reads/documents.json");
    let edges = f["data"]["viewer"]["documents"]["edges"]
        .as_array()
        .expect("relay edges");
    for e in edges {
        let n = &e["node"];
        assert!(n["id"].is_string());
        // Live-verified interface fields: `name` and `type` (the guessed
        // title/category/fileName do not exist on the schema).
        assert!(n["name"].is_string());
        assert!(n["date"].is_string());
        assert!(n["type"].is_string());
        assert!(n["accountName"]["subLabel"].is_string());
        // `url` is deliberately NOT selected by DocumentList: a pre-signed URL
        // is a live credential, and downloads re-derive it at fetch time.
        assert!(n.get("url").is_none(), "url must stay out of the listing");
    }
}

/// The consolidated 1099 is the reason this household wants the tool, so keep a
/// row that exercises the tax-form path end to end.
#[test]
fn documents_include_a_consolidated_1099_row() {
    let f = fixture("reads/documents.json");
    let has_1099 = f["data"]["viewer"]["documents"]["edges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| {
            e["node"]["name"]
                .as_str()
                .is_some_and(|t| t.contains("1099"))
        });
    assert!(has_1099, "no 1099 row to exercise the tax-form path");
}

/// The unauthenticated liveness probe. `Query.system` is `SystemInfo!` and
/// `status` is a `SystemStatusEnum`; a rename here would silently blank the
/// one field `m1f status` leads with.
#[test]
fn system_status_carries_the_status_enum() {
    let f = fixture("reads/system-status.json");
    let sys = &f["data"]["system"];
    assert!(sys["status"].is_string(), "status feeds the lead column");
    assert!(sys["isStatusBlocking"].is_boolean());
    // `version` and `statusMessage` are optional; only their presence-or-null
    // is contractual, not a value.
    assert!(sys.get("version").is_some());
    assert!(sys.get("statusMessage").is_some());
}

/// The FDX transaction ledger: `Account.fdxTransactions`. The two variants
/// alias `transactionType` differently (`investmentType` / `depositType`)
/// because their enums conflict — this pins that the fixture keeps both, so a
/// regression to a single name (which the server rejects) fails loudly here.
#[test]
fn transactions_carry_the_fdx_fields_and_aliased_types() {
    let f = fixture("reads/transactions.json");
    let conn = &f["data"]["node"]["fdxTransactions"];
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    let edges = conn["edges"].as_array().expect("relay edges");
    assert!(!edges.is_empty());
    for e in edges {
        let n = &e["node"];
        assert!(n["id"].is_string());
        assert!(n["amount"].is_number());
        assert!(n["debitCreditMemo"].is_string());
        assert!(n["transactionTimestamp"].is_string());
    }
    let invest = edges
        .iter()
        .find(|e| e["node"]["__typename"] == "FdxInvestmentTransaction")
        .expect("fixture should carry an investment transaction");
    assert!(invest["node"]["investmentType"].is_string());
    assert!(invest["node"]["symbol"].is_string());
    assert!(invest["node"]["units"].is_number());
    let deposit = edges
        .iter()
        .find(|e| e["node"]["__typename"] == "FdxDepositTransaction")
        .expect("fixture should carry a deposit transaction");
    assert!(deposit["node"]["depositType"].is_string());
}

/// Per-account summary: the account-level investment rollup nothing else
/// surfaces. A rename of `totalUnrealizedGain.gainPercent` or the funding
/// fields would silently drop the "how is this account doing" figures.
#[test]
fn summary_carries_the_account_rollup() {
    let f = fixture("reads/summary.json");
    let node = &f["data"]["node"];
    assert!(node["balance"]["totalValue"]["value"].is_number());
    let inv = &node["balance"]["investments"];
    assert!(inv["totalCost"]["cost"].is_number());
    assert!(inv["totalUnrealizedGain"]["gain"].is_number());
    assert!(inv["totalUnrealizedGain"]["gainPercent"].is_number());
    let funding = node["fundingTotals"]["totalsByYear"]
        .as_array()
        .expect("funding by year");
    assert!(!funding.is_empty());
    for y in funding {
        assert!(y["year"].is_number());
        assert!(y["totalDeposits"].is_number());
        assert!(y["totalWithdrawals"].is_number());
    }
}

/// IRA contributions: `iraContributionTotals.totalsByYear` with the exact
/// field spellings the remaining-room math reads.
#[test]
fn ira_contributions_carry_year_totals_and_limits() {
    let f = fixture("reads/ira.json");
    let node = &f["data"]["node"];
    assert!(node["registration"].is_string());
    assert!(node["iraContributionLimits"]["currentYearLimit"].is_number());
    let years = node["iraContributionTotals"]["totalsByYear"]
        .as_array()
        .expect("per-year totals");
    assert!(!years.is_empty());
    for y in years {
        assert!(y["year"].is_number());
        assert!(y["totalContribution"].is_number());
        assert!(y["maxContribution"].is_number());
    }
    // A year with a fractional contribution must exist so the exact-cents
    // remaining math is exercised against the fixture shape.
    let any_fractional = years
        .iter()
        .any(|y| y["totalContribution"].as_f64().unwrap_or(0.0).fract() > 0.0);
    assert!(
        any_fractional,
        "fixture should exercise a fractional contribution"
    );
}

/// Net worth: M1's `overview.balances` rollup. A rename of `total` or
/// `accountTotals` would silently empty the headline this command exists for.
#[test]
fn net_worth_carries_the_rollup_fields() {
    let f = fixture("reads/net-worth.json");
    let b = &f["data"]["viewer"]["overview"]["balances"];
    assert!(b["total"].is_number(), "total is the headline figure");
    assert!(b["assets"]["value"].is_number());
    assert!(b["isStatusBlocking"].is_null()); // sanity: not the status shape
    let totals = b["accountTotals"]
        .as_array()
        .expect("per-product breakdown");
    assert!(!totals.is_empty());
    for t in totals {
        assert!(t["type"].is_string());
        assert!(t["total"].is_number());
    }
}

/// Transfers: `viewer.transfers.pastInstances`. `status` is an OBJECT with a
/// `code`, not a scalar — a rename to a flat string would break `transfer_dto`.
#[test]
fn transfers_carry_status_object_and_amount() {
    let f = fixture("reads/transfers.json");
    let conn = &f["data"]["viewer"]["transfers"]["pastInstances"];
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    let edges = conn["edges"].as_array().expect("relay edges");
    assert!(!edges.is_empty());
    for e in edges {
        let n = &e["node"];
        assert!(n["id"].is_string());
        assert!(n["amount"].is_number());
        assert!(n["status"]["code"].is_string(), "status is an object");
    }
    // A pending transfer with a null endDate must be representable.
    let any_pending = edges
        .iter()
        .any(|e| e["node"]["status"]["code"] == "PENDING");
    assert!(any_pending, "fixture should exercise a pending transfer");
}

/// Holdings dividend enrichment: `Position.dividends`. `dividendYield` drives
/// the new column; `lastTwelveMonthsPaid` is a display string that can be the
/// placeholder "$--", which the DTO must drop.
#[test]
fn holdings_carry_dividend_detail() {
    let f = fixture("reads/holdings.json");
    let edges = f["data"]["node"]["balance"]["investments"]["positions"]["edges"]
        .as_array()
        .unwrap();
    let with_div = edges
        .iter()
        .find(|e| e["node"]["dividends"].is_object())
        .expect("fixture should carry dividend detail");
    let d = &with_div["node"]["dividends"];
    assert!(d["dividendYield"].is_number());
    assert!(d["dividendFrequency"].is_string());
    // The "$--" placeholder must appear on at least one position so the
    // drop-the-placeholder path is exercised.
    let any_placeholder = edges
        .iter()
        .any(|e| e["node"]["dividends"]["lastTwelveMonthsPaid"] == "$--");
    assert!(
        any_placeholder,
        "fixture should exercise the $-- placeholder"
    );
}

/// The tax-lot surface: the reason this CLI exists. Asserts the live-verified
/// field spellings that Form 8949 work depends on.
#[test]
fn lots_carry_the_8949_fields() {
    let f = fixture("reads/lots.json");
    let conn = &f["data"]["node"]["taxLots"];
    assert!(conn["totalCount"].is_number());
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    let edges = conn["edges"].as_array().expect("relay edges");
    for e in edges {
        let n = &e["node"];
        assert!(n["id"].is_string());
        assert!(n["symbol"].is_string());
        assert!(n["acquisitionDate"].is_string());
        assert!(n["quantity"].is_number());
        assert!(n["costBasis"].is_number());
        // The live spelling is washSaleIndicator, not isWashSale.
        assert!(n["washSaleIndicator"].is_boolean());
    }
    // The fixture must exercise a closed lot with a realized loss and a
    // wash-sale disallowance — the 8949 shapes that matter.
    let any_wash = edges.iter().any(|e| {
        e["node"]["washSaleIndicator"] == true && e["node"]["disallowedWashSaleAmount"].is_number()
    });
    assert!(any_wash, "fixture should exercise a wash-sale lot");
    let any_loss = edges.iter().any(|e| {
        e["node"]["shortTermRealizedGainLoss"]
            .as_f64()
            .unwrap_or(0.0)
            < 0.0
    });
    assert!(any_loss, "fixture should exercise a realized loss");
}

/// The MFA demand and a plain credential failure are the *same* shape —
/// `didSucceed: false` with a scalar `error`. Only the text distinguishes them,
/// which is why `needs_email_code` sniffs the string and fails safe.
#[test]
fn an_mfa_demand_is_shaped_exactly_like_a_failure() {
    let mfa = fixture("auth/authenticate-mfa.json");
    let bad = fixture("auth/authenticate-failure.json");
    for f in [&mfa, &bad] {
        assert_eq!(f["data"]["authenticate"]["didSucceed"], false);
        assert!(f["data"]["authenticate"]["error"].is_string());
        assert!(f["data"]["authenticate"]["outcome"].is_null());
        assert!(f.get("errors").is_none());
    }
    // The only signal is the enum member. Verified live 2026-08-13: M1 emits
    // EMAIL_AMFA_REQUIRED (email path) and the schema also carries
    // CODE_REQUIRED; both must be recognized by `needs_email_code`.
    let text = mfa["data"]["authenticate"]["error"].as_str().unwrap();
    assert_eq!(text, "EMAIL_AMFA_REQUIRED");
}

/// `dividends list` reads the activity feed through its dividend category
/// filter. Live 2026-09-23: every entry it returns is an
/// `InvestActivityCashEntry` titled "Dividend" with an EMPTY description, a
/// `Float` amount, the symbol under `cashSecurity`, and a UTC midnight-Eastern
/// timestamp as the date.
#[test]
fn dividends_are_cash_entries_with_symbol_amount_and_date() {
    let f = fixture("reads/dividends.json");
    let conn = &f["data"]["node"]["investActivity"]["activity"];
    assert!(conn["pageInfo"]["hasNextPage"].is_boolean());
    let edges = conn["edges"].as_array().expect("edges");
    assert!(!edges.is_empty());
    for e in edges {
        let n = &e["node"];
        assert_eq!(n["__typename"], "InvestActivityCashEntry");
        assert_eq!(n["title"], "Dividend");
        assert_eq!(
            n["description"], "",
            "live dividends carry an empty description"
        );
        assert!(n["amount"].is_f64(), "amount is a Float");
        assert!(n["cashSecurity"]["symbol"].is_string());
        let date = n["date"].as_str().expect("date");
        assert!(date.contains('T') && date.ends_with('Z'), "{date}");
    }
}

/// `Account.isRetirement` is what lets a consumer leave IRA dividends out of
/// taxable income; the fixture carries it on every account.
#[test]
fn accounts_carry_the_retirement_flag() {
    let f = fixture("reads/accounts.json");
    for e in f["data"]["viewer"]["accounts"]["edges"].as_array().unwrap() {
        let n = &e["node"];
        let ira = n["registration"].as_str().unwrap().ends_with("_IRA");
        assert_eq!(n["isRetirement"].as_bool(), Some(ira), "{n}");
    }
}

/// `net-worth` splits the Invest line by account from the same account
/// nodes: each carries the id, a registration the family type maps, the
/// retirement flag, and the `balance.totalValue { value hasValue }` wrapper
/// the per-account total reads.
#[test]
fn accounts_carry_what_the_net_worth_split_reads() {
    let f = fixture("reads/accounts.json");
    for e in f["data"]["viewer"]["accounts"]["edges"].as_array().unwrap() {
        let n = &e["node"];
        assert!(n["id"].is_string(), "{n}");
        assert!(n["registration"].is_string(), "{n}");
        assert!(n["isRetirement"].is_boolean(), "{n}");
        assert!(n["status"].is_string(), "{n}");
        let total = &n["balance"]["totalValue"];
        assert!(total["value"].is_number(), "{n}");
        assert!(total["hasValue"].is_boolean(), "{n}");
    }
}

/// The browser-session login reads auth0-spa-js's cache entry: the token
/// pair under `body`, the audience it checks, and the absolute `expiresAt`.
#[test]
fn the_auth0_cache_entry_carries_what_the_session_reader_reads() {
    let f = fixture("auth/auth0-spa-cache.json");
    let body = &f["body"];
    assert!(body["access_token"].is_string());
    assert!(body["refresh_token"].is_string());
    assert_eq!(body["audience"], "https://lens.m1finance.com");
    assert!(body["client_id"].is_string());
    assert!(body["expires_in"].is_number());
    assert!(f["expiresAt"].is_number());
}

/// The verification read is one boolean, and only `true` passes.
#[test]
fn the_session_check_is_one_boolean() {
    let f = fixture("reads/viewer-is-authenticated.json");
    assert_eq!(f["data"]["viewer"]["isAuthenticated"], true);
}
