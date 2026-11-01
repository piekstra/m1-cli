//! Turning M1's GraphQL responses into DTO values.
//!
//! Two principles, both learned the expensive way on unofficial APIs:
//!
//! 1. **A shape mismatch must fail loudly.** If the field we expect is gone,
//!    returning an empty list renders as "you have no holdings" — indis-
//!    tinguishable from a genuinely empty account, and wrong in a way nobody
//!    notices until it matters. Every accessor here errors instead.
//! 2. **Be liberal about container shape, strict about presence.** Relay
//!    connections (`edges[].node`), `nodes[]`, and plain arrays all mean the
//!    same thing, and a provider can migrate between them without warning. We
//!    accept all three, but we do not paper over a missing field.

use pk_cli_core::{CliError, Money};
use serde_json::Value;

/// Walk a dotted path through an object, erroring with the full path when a
/// segment is missing so the message says exactly where the shape diverged.
pub fn at<'a>(data: &'a Value, path: &[&str]) -> Result<&'a Value, CliError> {
    let mut cur = data;
    for (i, seg) in path.iter().enumerate() {
        cur = cur.get(seg).ok_or_else(|| {
            CliError::Upstream(format!(
                "unexpected response shape from M1: no `{}` at `{}` — the API may have \
                 changed (see docs/api.md)",
                seg,
                path[..=i].join(".")
            ))
        })?;
    }
    Ok(cur)
}

/// Fail with NOT FOUND when a `node(id:)` lookup answered `null` — that is
/// "no such account for this login" (a mistyped or stale `--account`), not a
/// shape change, and telling the user the API changed sends them debugging
/// the wrong thing.
pub fn require_node(data: &Value) -> Result<(), CliError> {
    match data.get("node") {
        Some(Value::Null) => Err(CliError::NotFound(
            "no account with that id on this login — check `m1f accounts list`".into(),
        )),
        _ => Ok(()),
    }
}

/// The list of records at `path`, accepting any of the three container shapes.
///
/// A JSON `null` at the path is treated as an empty list: GraphQL nulls a
/// nullable field the caller has no access to, which is legitimately "nothing
/// here" rather than a shape change.
pub fn nodes(data: &Value, path: &[&str]) -> Result<Vec<Value>, CliError> {
    let container = at(data, path)?;
    collect(container).ok_or_else(|| {
        CliError::Upstream(format!(
            "unexpected response shape from M1: `{}` is neither a list, a `nodes` \
             list, nor a Relay `edges` connection (see docs/api.md)",
            path.join(".")
        ))
    })
}

fn collect(container: &Value) -> Option<Vec<Value>> {
    match container {
        Value::Null => Some(vec![]),
        Value::Array(items) => Some(items.clone()),
        Value::Object(_) => {
            if let Some(nodes) = container.get("nodes").and_then(Value::as_array) {
                return Some(nodes.clone());
            }
            if let Some(edges) = container.get("edges").and_then(Value::as_array) {
                return Some(
                    edges
                        .iter()
                        .map(|e| e.get("node").cloned().unwrap_or(Value::Null))
                        .collect(),
                );
            }
            None
        }
        _ => None,
    }
}

/// The Relay cursor for the next page, if the connection advertises one.
pub fn next_cursor(container: &Value) -> Option<String> {
    let info = container.get("pageInfo")?;
    if info.get("hasNextPage").and_then(Value::as_bool) == Some(true) {
        return info
            .get("endCursor")
            .and_then(Value::as_str)
            .map(str::to_string);
    }
    None
}

/// An id that may arrive as a string or a number — GraphQL `ID` serializes as
/// a string, but unofficial gateways are inconsistent.
pub fn id(v: &Value, key: &str) -> Result<String, CliError> {
    match v.get(key) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Number(n)) => Ok(n.to_string()),
        _ => Err(CliError::Upstream(format!(
            "unexpected response shape from M1: record is missing id field `{key}`"
        ))),
    }
}

/// Decode one of M1's Relay-style node ids: base64 of
/// `TypeName:{…json…}`. Returns the inner JSON value (the part after the first
/// `{`), or None if the blob isn't shaped that way.
///
/// These ids are **credential-bearing** — a document blob embeds the account
/// number and a signed URL, a transfer blob embeds the raw transfer id — so a
/// caller decodes to the stable inner field and never emits the raw blob.
pub fn decode_relay_blob(raw: &str) -> Option<Value> {
    let bytes = base64_decode(raw)?;
    let text = String::from_utf8(bytes).ok()?;
    let json_part = &text[text.find('{')?..];
    serde_json::from_str(json_part).ok()
}

/// Standard/URL-safe base64, padding optional. Hand-rolled to keep the
/// dependency tree flat for a small need; not a general-purpose decoder.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in s.as_bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// A numeric field rendered as a plain string decimal — for share counts and
/// lot quantities, which are fractional and must never render with a currency
/// symbol or be rounded to an integer. A string passes through verbatim; a
/// JSON number uses its lossless decimal form.
pub fn decimal_string(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// An optional string field (absent and null both mean "not provided").
pub fn opt_string(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Money, however it arrives.
///
/// Never goes through `f64` for a value that is already exact: a string
/// decimal is passed through as-is, and an integer minor-unit value uses
/// integer math. Only a JSON float has to be formatted, and it is pinned to
/// two places so `12.1` doesn't render as `$12.1`.
pub fn money(v: &Value) -> Option<Money> {
    match v {
        Value::String(s) => Money::parse_usd(s).or_else(|| Some(Money::usd(s.clone()))),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                // A bare integer is dollars here, not cents: M1's web payloads
                // carry decimal dollars. `from_cents` would be a 100x error.
                Some(Money::usd(format!("{i}.00")))
            } else {
                n.as_f64().map(|f| Money::usd(format!("{f:.2}")))
            }
        }
        Value::Object(_) => {
            let currency = v
                .get("currency")
                .and_then(Value::as_str)
                .unwrap_or("USD")
                .to_string();
            let amount = v.get("amount").or_else(|| v.get("value"))?;
            let mut m = money(amount)?;
            m.currency = currency;
            Some(m)
        }
        _ => None,
    }
}

/// A two-decimal amount string (`"1234.50"`, `"-0.05"`) as integer cents —
/// the only form money arithmetic here takes, never a float. `None` when it
/// does not read as a decimal (rather than guessing); a third decimal place
/// is truncated, which `Money`'s own two-place amounts never carry. A
/// doubled or inner sign, and an amount past `i64` cents, are `None`.
pub fn cents(amount: &str) -> Option<i64> {
    let s = amount.trim();
    // At most one leading minus; `i64::parse` would accept a sign of its
    // own in either part, so both parts are held to ASCII digits below.
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    let digits = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || !digits(whole) || !digits(frac) {
        return None;
    }
    let frac = format!("{frac:0<2}");
    let cents = whole
        .parse::<i64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(frac.get(..2)?.parse::<i64>().ok()?)?;
    Some(if neg { -cents } else { cents })
}

/// Money at `key`, or zero USD when absent — for totals that legitimately read
/// as 0 rather than "unknown".
pub fn money_at(v: &Value, key: &str) -> Option<Money> {
    v.get(key).and_then(money)
}

/// Normalize any of M1's date spellings to ISO `YYYY-MM-DD`.
///
/// Accepts a full RFC 3339 timestamp, a bare ISO date, or a Unix epoch in
/// seconds. Provider formats are an internal concern; every date this CLI
/// emits is ISO.
pub fn iso_date(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => {
            let s = s.trim();
            // `s.get(..10)` rather than `s[..10]`: a malformed value from this
            // unofficial API could put a multi-byte char across byte 10, and a
            // fixed-offset slice would panic instead of failing loudly as this
            // module promises. `get` returns None on a non-char-boundary.
            if s.as_bytes().get(4) == Some(&b'-') && s.as_bytes().get(7) == Some(&b'-') {
                if let Some(head) = s.get(..10) {
                    return Some(head.to_string());
                }
            }
            None
        }
        Value::Number(n) => n
            .as_i64()
            .map(|secs| pk_cli_core::dates::fmt_iso(pk_cli_core::dates::civil_from_unix(secs))),
        _ => None,
    }
}

/// A timestamp kept at full precision (for `expires_at`, where the time of day
/// matters), normalizing an epoch number to RFC 3339.
pub fn iso_or_rfc3339(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => {
            let s = s.trim();
            (!s.is_empty()).then(|| s.to_string())
        }
        Value::Number(n) => n.as_i64().map(pk_cli_core::dates::fmt_rfc3339),
        _ => None,
    }
}

/// `iso_date` at the first key that is present, so a rename between e.g.
/// `date` and `createdAt` doesn't need a code change at every call site.
pub fn date_at(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| v.get(k).and_then(iso_date))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn at_names_the_exact_path_that_diverged() {
        let data = json!({ "viewer": { "accounts": [] } });
        let err = at(&data, &["viewer", "holdings", "edges"]).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("viewer.holdings"), "{err}");
    }

    #[test]
    fn nodes_accepts_a_plain_array() {
        let d = json!({ "a": { "b": [{"id": "1"}] } });
        assert_eq!(nodes(&d, &["a", "b"]).unwrap().len(), 1);
    }

    #[test]
    fn nodes_accepts_a_nodes_list() {
        let d = json!({ "a": { "b": { "nodes": [{"id": "1"}, {"id": "2"}] } } });
        assert_eq!(nodes(&d, &["a", "b"]).unwrap().len(), 2);
    }

    #[test]
    fn nodes_accepts_a_relay_connection() {
        let d = json!({ "a": { "b": { "edges": [{ "node": {"id": "1"} }] } } });
        let got = nodes(&d, &["a", "b"]).unwrap();
        assert_eq!(got[0]["id"], json!("1"));
    }

    #[test]
    fn nodes_treats_null_as_empty_but_a_scalar_as_a_shape_change() {
        let d = json!({ "a": { "b": null } });
        assert!(nodes(&d, &["a", "b"]).unwrap().is_empty());
        let bad = json!({ "a": { "b": 42 } });
        assert_eq!(nodes(&bad, &["a", "b"]).unwrap_err().exit_code(), 5);
    }

    #[test]
    fn next_cursor_only_when_there_is_a_next_page() {
        let more = json!({ "pageInfo": { "hasNextPage": true, "endCursor": "abc" } });
        assert_eq!(next_cursor(&more).as_deref(), Some("abc"));
        let done = json!({ "pageInfo": { "hasNextPage": false, "endCursor": "abc" } });
        assert_eq!(next_cursor(&done), None);
        assert_eq!(next_cursor(&json!({})), None);
    }

    #[test]
    fn id_accepts_strings_and_numbers() {
        assert_eq!(id(&json!({"id": "a1"}), "id").unwrap(), "a1");
        assert_eq!(id(&json!({"id": 17}), "id").unwrap(), "17");
        assert!(id(&json!({}), "id").is_err());
    }

    #[test]
    fn money_handles_the_shapes_a_gateway_might_send() {
        assert_eq!(money(&json!("12.34")).unwrap().amount, "12.34");
        assert_eq!(money(&json!("$1,234.50")).unwrap().amount, "1234.50");
        assert_eq!(money(&json!(12.1)).unwrap().amount, "12.10");
        assert_eq!(money(&json!(5)).unwrap().amount, "5.00");
        let obj = money(&json!({"amount": "9.99", "currency": "EUR"})).unwrap();
        assert_eq!(
            (obj.amount.as_str(), obj.currency.as_str()),
            ("9.99", "EUR")
        );
    }

    #[test]
    fn cents_reads_two_place_amounts_exactly() {
        assert_eq!(cents("1234.50"), Some(123_450));
        assert_eq!(cents("-0.05"), Some(-5));
        assert_eq!(cents("7"), Some(700));
        assert_eq!(cents("7.5"), Some(750));
        assert_eq!(cents(""), None);
        assert_eq!(cents("$7.50"), None);
        assert_eq!(cents("abc"), None);
    }

    #[test]
    fn cents_refuses_doubled_and_inner_signs_and_overflow() {
        assert_eq!(cents("--5"), None);
        assert_eq!(cents("7.-5"), None);
        assert_eq!(cents("7.+5"), None);
        assert_eq!(cents("+7"), None);
        assert_eq!(cents("-"), None);
        // i64::MAX dollars has no cents representation: refused, not wrapped.
        assert_eq!(cents(&i64::MAX.to_string()), None);
        assert_eq!(cents("92233720368547758.07"), Some(i64::MAX));
    }

    #[test]
    fn a_negative_amount_survives() {
        assert_eq!(money(&json!("-3.50")).unwrap().amount, "-3.50");
        assert_eq!(money(&json!("(3.50)")).unwrap().amount, "-3.50");
    }

    #[test]
    fn iso_date_normalizes_timestamps_and_epochs() {
        assert_eq!(
            iso_date(&json!("2026-08-11")).as_deref(),
            Some("2026-08-11")
        );
        assert_eq!(
            iso_date(&json!("2026-08-11T14:03:00Z")).as_deref(),
            Some("2026-08-11")
        );
        assert_eq!(iso_date(&json!("nope")), None);
        // 1786406400 == 2026-08-11T00:00:00Z
        assert_eq!(
            iso_date(&json!(1786406400_i64)).as_deref(),
            Some("2026-08-11")
        );
    }

    /// A malformed value with a multi-byte char straddling byte 10 must return
    /// None, not panic on a non-char-boundary slice.
    #[test]
    fn iso_date_does_not_panic_on_a_multibyte_boundary() {
        // "2026-08-1" is 9 ASCII bytes; the "é" (2 bytes) starts at byte 9, so
        // byte index 10 lands inside it. Bytes 4 and 7 are '-', passing the
        // cheap check, so the slice would be reached.
        assert_eq!(iso_date(&json!("2026-08-1é9")), None);
        // A short value that passes the dash check but has no 10th byte.
        assert_eq!(iso_date(&json!("2026-08-9")), None);
    }

    #[test]
    fn decimal_string_preserves_fractions_and_strings() {
        assert_eq!(
            decimal_string(&json!({ "q": 0.12345 }), "q").as_deref(),
            Some("0.12345")
        );
        assert_eq!(
            decimal_string(&json!({ "q": "1.5" }), "q").as_deref(),
            Some("1.5")
        );
        assert_eq!(decimal_string(&json!({ "q": null }), "q"), None);
        assert_eq!(decimal_string(&json!({}), "q"), None);
    }

    #[test]
    fn date_at_takes_the_first_present_key() {
        let v = json!({ "createdAt": "2026-01-02T00:00:00Z" });
        assert_eq!(
            date_at(&v, &["date", "createdAt"]).as_deref(),
            Some("2026-01-02")
        );
        assert_eq!(date_at(&v, &["nope"]), None);
    }
}
