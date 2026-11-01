//! GraphQL transport for M1's private backend.
//!
//! # The one invariant
//!
//! **HTTP status tells you almost nothing here.** GraphQL answers `200 OK` for
//! success, for an expired token, for a malformed query, for a rate-limit, and
//! for a permissions failure. The signal is the `errors` array in the response
//! body. Every response in this CLI goes through [`M1Client::execute`], which
//! inspects that array *before* it looks at anything else, so there is exactly
//! one place that decides whether a call succeeded.
//!
//! The subtle case is the **partial response**: GraphQL may return some `data`
//! alongside `errors` when a nullable field fails. Rendering that as success
//! would silently show a half-empty portfolio. We treat any populated `errors`
//! array as a failure, whatever `data` holds.

use pk_cli_core::CliError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// M1's web dashboard, which this client presents itself as.
pub const WEB_ORIGIN: &str = "https://dashboard.m1.com";
pub const WEB_REFERER: &str = "https://dashboard.m1.com/";

/// The `x-client-id` M1's web app sends. The version was observed live at
/// 10.0.272 (2026-08-13) and read from the dashboard bundle's Apollo link at
/// 10.0.312 (2026-10-27); it is cosmetic to us but Cloudflare may care that
/// it is present and well-formed.
pub const CLIENT_ID: &str = "m1-web/10.0.312";

/// Milliseconds since the epoch, as a string — the `x-client-sentinel` shape.
fn sentinel() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().to_string())
        .unwrap_or_else(|_| "0".into())
}

/// A stable, UUIDv4-shaped `x-segment-id`.
///
/// M1's web app persists a random UUID in browser storage. We need the same
/// property — *stable across runs on this machine* — so we derive it from
/// machine-local identifiers rather than storing yet another file. It is an
/// analytics correlator, not a credential and not a secret; deriving it means
/// there is no new persisted identifier to leak or to keep in sync.
fn segment_id() -> String {
    let seed = format!(
        "m1f:{}:{}",
        std::env::var("USER").unwrap_or_default(),
        std::env::var("HOME").unwrap_or_default()
    );
    // FNV-1a, run over four offsets to fill 16 bytes. Not cryptographic and
    // does not need to be: the only requirement is stability.
    let mut bytes = [0u8; 16];
    for (i, chunk) in bytes.chunks_mut(8).enumerate() {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ (i as u64);
        for b in seed.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        chunk.copy_from_slice(&h.to_be_bytes());
    }
    // Set the version (4) and variant (RFC 4122) nibbles so it is a
    // well-formed v4 UUID rather than merely 32 hex characters.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let h: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let h = h.join("");
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Token bundle persisted in the OS keychain under `piekstra.m1f`.
///
/// Serialized as JSON into a single keychain entry so the access token,
/// refresh token, and expiry rotate together — a half-updated pair is an
/// authentication failure that looks like a provider outage.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBundle {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// RFC 3339. Advisory only — the server is the authority on expiry, so a
    /// token that looks live can still come back `UNAUTHENTICATED`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Which login minted the bundle, and so which refresh renews it: `None`
    /// is the legacy `Authenticate` mutation (renewed by `Reauthenticate`),
    /// `Some` a browser session from M1's Auth0 tenant (renewed at its token
    /// endpoint, `crate::auth0`). Absent in a bundle stored before the
    /// browser-session login existed, which reads as legacy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth0: Option<crate::auth0::Auth0Grant>,
}

impl TokenBundle {
    /// The login that replaces this bundle when its refresh token is gone
    /// (with `--overwrite`, since this one is still stored).
    pub fn login_hint(&self) -> &'static str {
        if self.auth0.is_some() {
            crate::auth0::RELOGIN
        } else {
            "m1f auth login"
        }
    }
}

/// An authentication attempt parked mid-flight because the provider demanded a
/// verification code.
///
/// Kept in the keychain so a follow-up `auth login --code <CODE>` resumes *this*
/// challenge. Starting a fresh login instead would present the code against a
/// session that never requested one — which fails in a way that reads like a
/// wrong code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingChallenge {
    /// Opaque handle the provider uses to tie the code to this attempt.
    pub challenge_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
}

pub struct M1Client {
    http: reqwest::blocking::Client,
    endpoint: String,
    token: Option<String>,
    verbose: bool,
}

impl M1Client {
    pub fn new(endpoint: &str, token: Option<String>, verbose: bool) -> Result<Self, CliError> {
        let http = pk_cli_http::client("m1f", env!("CARGO_PKG_VERSION"))?;
        Ok(Self {
            http,
            endpoint: endpoint.to_string(),
            token,
            verbose,
        })
    }

    /// Unauthenticated client, for the login mutation itself.
    pub fn anonymous(endpoint: &str, verbose: bool) -> Result<Self, CliError> {
        Self::new(endpoint, None, verbose)
    }

    /// Send a GraphQL operation and return its `data` object.
    ///
    /// Failure classification is delegated to [`classify_errors`] so it can be
    /// unit-tested offline against real error envelopes.
    pub fn execute(
        &self,
        query: &str,
        variables: Value,
        operation_name: Option<&str>,
    ) -> Result<Value, CliError> {
        self.execute_with(query, variables, operation_name, html_error)
    }

    /// [`execute`](Self::execute), with the caller's reading of an HTML answer
    /// (a Cloudflare page where GraphQL should be). The password login uses it
    /// to name the 403 trap rather than send the owner back to the login that
    /// just failed.
    pub fn execute_with(
        &self,
        query: &str,
        variables: Value,
        operation_name: Option<&str>,
        on_html: impl FnOnce(reqwest::StatusCode) -> CliError,
    ) -> Result<Value, CliError> {
        let mut body = json!({ "query": query, "variables": variables });
        if let Some(name) = operation_name {
            body["operationName"] = json!(name);
        }

        if self.verbose {
            // Shape only — never the Authorization header, never variables,
            // which can carry a password on the login path.
            eprintln!(
                "POST {} ({} bytes, operation {})",
                self.endpoint,
                query.len(),
                operation_name.unwrap_or("<anonymous>")
            );
        }

        let mut req = self
            .http
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            // M1's own web client sends these. They are not authentication —
            // they identify the caller to Cloudflare bot management, which sits
            // in front of this endpoint. Without them a request is more likely
            // to be answered with an interstitial HTML challenge than with
            // GraphQL, which `looks_like_html` below turns into a clear error.
            .header("apollographql-client-name", "m1-web")
            .header("x-client-id", CLIENT_ID)
            .header("x-client-sentinel", sentinel())
            .header("x-segment-id", segment_id())
            .header("origin", WEB_ORIGIN)
            .header("referer", WEB_REFERER);
        if let Some(name) = operation_name {
            req = req.header("x-apollo-operation-name", name);
        }
        if let Some(t) = &self.token {
            req = req.header("authorization", format!("Bearer {t}"));
        }

        let resp = req.json(&body).send()?;
        let status = resp.status();
        let text = resp.text()?;

        // A non-JSON body is the other way this fails: an HTML login page, a
        // CDN error page, or a WAF challenge. Those are not GraphQL at all.
        let payload: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) if looks_like_html(&text) => return Err(on_html(status)),
            Err(_) => {
                return Err(CliError::Upstream(format!(
                    "unparseable response from M1 (HTTP {status}, {} bytes)",
                    text.len()
                )))
            }
        };

        // The envelope check comes FIRST, before status, because a populated
        // `errors` array arrives with HTTP 200 in the overwhelming majority of
        // failures.
        if let Some(errors) = payload.get("errors").and_then(Value::as_array) {
            if !errors.is_empty() {
                if self.verbose {
                    // A REDACTED view, not the raw array. The envelope is useful
                    // for schema discovery (the real `code` / `isAuthError`
                    // shape), but `--verbose` must never print account data
                    // (SECURITY.md), and on this reverse-engineered API an error
                    // `message` or `extensions` can echo request context — M1
                    // demonstrably embeds account numbers in id blobs elsewhere.
                    // So we allowlist known-safe fields per error rather than
                    // trusting the whole object.
                    eprintln!("raw errors: {}", redact_errors(errors));
                }
                return Err(classify_errors(errors));
            }
        }

        // Only now does status matter — this catches infrastructure failures
        // that never reached the GraphQL layer (502 from a proxy, 429 from a
        // CDN) and so carry no `errors` array.
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => CliError::Auth(format!(
                    "M1 rejected the request (HTTP {status}) — try `m1f auth login`"
                )),
                429 => CliError::Upstream(
                    "rate limited by M1 (HTTP 429) — wait before retrying".into(),
                ),
                _ => CliError::Upstream(format!("M1 returned HTTP {status}")),
            });
        }

        match payload.get("data") {
            // `data: null` with no errors is malformed, but has been observed
            // from GraphQL gateways under load. Treat it as upstream, not as an
            // empty result, so it never renders as "you have no accounts".
            None | Some(Value::Null) => Err(CliError::Upstream(
                "M1 returned no data and no errors — the API shape may have changed".into(),
            )),
            Some(data) => Ok(data.clone()),
        }
    }
}

impl M1Client {
    /// Fetch a document's bytes from a download URL.
    ///
    /// Kept separate from `execute` because this is a plain HTTP GET, not
    /// GraphQL: there is no `errors` envelope, so here the status *is* the
    /// signal. Pre-signed URLs carry their own credentials and expire, so a
    /// stale one shows up as 403 — reported as an auth error pointing at a
    /// re-list rather than a re-login.
    pub fn download(&self, url: &str) -> Result<Vec<u8>, CliError> {
        if self.verbose {
            eprintln!("GET <document url> ({} bytes of url)", url.len());
        }
        let mut req = self.http.get(url);
        // Only attach the bearer to M1's own hosts; a pre-signed URL on a CDN
        // can reject a request that carries an unexpected Authorization header.
        if let Some(t) = &self.token {
            if url.contains("m1.com") || url.contains("m1finance.com") {
                req = req.header("authorization", format!("Bearer {t}"));
            }
        }
        let resp = req.send()?;
        let status = resp.status();
        if !status.is_success() {
            return Err(match status.as_u16() {
                401 | 403 => CliError::Auth(format!(
                    "M1 refused the document download (HTTP {status}) — the link may have \
                     expired; re-run `m1f documents list` for a fresh one"
                )),
                404 => CliError::NotFound("document not available at that URL".into()),
                _ => CliError::Upstream(format!("downloading the document: HTTP {status}")),
            });
        }
        let bytes = resp.bytes()?.to_vec();
        if bytes.is_empty() {
            return Err(CliError::Upstream(
                "M1 returned an empty document — treating as a failure rather than \
                 writing a 0-byte file"
                    .into(),
            ));
        }
        Ok(bytes)
    }
}

/// A `--verbose`-safe projection of a GraphQL `errors` array.
///
/// Keeps only the fields that aid schema discovery — `message`, `code`,
/// `isAuthError`, `name`, `path`, `extensions.code` — and passes the free-text
/// `message` through [`scrub`], because that is the one field that can echo a
/// submitted value. Everything else (raw `extensions`, `locations`, and any
/// field M1 might add) is dropped rather than trusted.
fn redact_errors(errors: &[Value]) -> String {
    let safe: Vec<Value> = errors
        .iter()
        .map(|e| {
            let mut out = serde_json::Map::new();
            if let Some(m) = e.get("message").and_then(Value::as_str) {
                out.insert("message".into(), Value::String(scrub(m)));
            }
            for key in ["code", "isAuthError", "name", "path"] {
                if let Some(v) = e.get(key) {
                    out.insert(key.into(), v.clone());
                }
            }
            if let Some(code) = e.get("extensions").and_then(|x| x.get("code")) {
                out.insert("extensions.code".into(), code.clone());
            }
            Value::Object(out)
        })
        .collect();
    serde_json::to_string(&safe).unwrap_or_default()
}

/// Mask the two shapes that can carry account data in an otherwise-useful
/// message: a long token (24+ chars of base64/URL-safe alphabet — an
/// account-id blob or a signed URL) and a run of 8+ digits (an account/SSN/card
/// number). Everything else passes through so the diagnostic stays legible.
///
/// Two independent passes, tokens THEN digits, because the two shapes overlap:
/// a digit run glued to a token prefix (`accountId=5551234567`, `acct-5551234567`)
/// must still be masked even though it sits inside a tokenish span shorter than
/// 24 — so the digit pass runs over the *whole* string, not only where a token
/// scan didn't already consume. Running tokens first means a real id blob is
/// masked as one unit before the digit pass can fragment it.
fn scrub(s: &str) -> String {
    mask_digit_runs(&mask_long_tokens(s))
}

/// Replace a maximal run of base64/URL-safe token characters with `<redacted>`
/// when it looks like an account-id blob or a pre-signed URL — **not** when it
/// is a plain identifier.
///
/// Length alone over-masks: `disallowedWashSaleAmount` (24) and
/// `InvestActivityTradeSummaryEntry` (31) are field/type names this CLI selects,
/// and the verbose dump exists precisely to surface the `errors[]` field name
/// when M1 renames one — masking it removes the signal. A real blob (base64 of
/// JSON, or a signed-URL parameter) effectively always contains a digit or a
/// `+`/`/`/`=`; a camelCase or SCREAMING_SNAKE identifier contains none. So mask
/// a 24+ run only when it is blob-shaped, with an unconditional 40+ backstop so
/// an all-letter blob still can't slip through.
fn mask_long_tokens(s: &str) -> String {
    let is_tokenish = |b: u8| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'_' || b == b'-' || b == b'='
    };
    mask_runs(s, is_tokenish, |run| {
        let blob_shaped = run
            .bytes()
            .any(|b| b.is_ascii_digit() || b == b'+' || b == b'/' || b == b'=');
        (run.len() >= 24 && blob_shaped) || run.len() >= 40
    })
}

/// Replace any maximal run of 8+ ASCII digits with `<redacted>` — the shape of
/// an account, SSN, or card number, wherever it appears (including glued to a
/// token prefix, which [`mask_long_tokens`] leaves intact when the span is
/// under 24 chars).
fn mask_digit_runs(s: &str) -> String {
    mask_runs(s, |b| b.is_ascii_digit(), |run| run.len() >= 8)
}

/// Replace every maximal run of bytes matching `in_class` that `should_mask`
/// accepts with `<redacted>`, copying everything else through char-by-char
/// (UTF-8 safe). The one scan loop both masking passes share; each supplies its
/// own class and its own accept rule (a length threshold, or length plus a
/// content test).
fn mask_runs(s: &str, in_class: impl Fn(u8) -> bool, should_mask: impl Fn(&str) -> bool) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if in_class(bytes[i]) {
            let start = i;
            while i < bytes.len() && in_class(bytes[i]) {
                i += 1;
            }
            if should_mask(&s[start..i]) {
                out.push_str("<redacted>");
            } else {
                out.push_str(&s[start..i]);
            }
            continue;
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// An HTML page where a read expected GraphQL: a Cloudflare bot check, or a
/// session the edge refused. Exit 3, pointing at the login that works today.
fn html_error(status: reqwest::StatusCode) -> CliError {
    CliError::Auth(format!(
        "expected a GraphQL response but got HTML (HTTP {status}) — a Cloudflare bot check \
         intervened or the session is no longer accepted; sign in again with `{}` (steps in \
         `m1f auth login --help`)",
        crate::auth0::RELOGIN
    ))
}

/// The password login's reading of an HTML answer — the 403 trap of
/// 2026-10-27 (docs/api.md, "Trap 7"): Cloudflare answers the legacy
/// `Authenticate` mutation with an HTML page while the unauthenticated
/// `status` probe still answers `NORMAL`. M1's web app no longer sends that
/// mutation (it signs in through Auth0), so retrying cannot help; the
/// browser-session login is the path that works.
pub fn legacy_login_blocked(status: reqwest::StatusCode) -> CliError {
    CliError::Auth(format!(
        "M1 answered the password login with an HTML page (HTTP {status}) instead of GraphQL: \
         its Cloudflare front refuses the legacy `Authenticate` mutation (seen since \
         2026-10-27; M1's own web app now signs in through Auth0). Retrying will not help and \
         nothing was stored. Sign in through M1's web app instead: `{}` (steps in `m1f auth \
         login --help`)",
        crate::auth0::LOGIN
    ))
}

pub fn looks_like_html(body: &str) -> bool {
    // Trim first, then take the window from the *trimmed* text. Slicing with
    // `get(..200).unwrap_or(body)` would silently fall back to the untrimmed
    // body for any response shorter than 200 bytes — which is exactly the short
    // redirect stub this is meant to catch.
    let trimmed = body.trim_start();
    let head = trimmed
        .char_indices()
        .nth(200)
        .map_or(trimmed, |(i, _)| &trimmed[..i])
        .to_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html") || head.contains("<title>")
}

/// Enforce a mutation payload's **own** success flag.
///
/// This is the second honesty trap on this API, one level below the `errors`
/// array. M1's `authenticate` payload is shaped
/// `{ didSucceed, error, outcome { accessToken … } }`: a wrong password comes
/// back as **HTTP 200, with no `errors` array at all**, and the only signal is
/// `didSucceed: false`. Code that checked the transport and the GraphQL
/// envelope — both of which look perfectly healthy — would conclude the login
/// worked and then store an empty token.
///
/// So any payload carrying `didSucceed` must be asked. Payloads that don't
/// carry it are passed through untouched.
pub fn check_did_succeed(data: &Value) -> Result<(), CliError> {
    let Some((node, ok)) = find_did_succeed(data, 6) else {
        return Ok(());
    };
    if ok {
        return Ok(());
    }
    let detail = node
        .get("error")
        .map(describe_error)
        .filter(|d| !d.is_empty())
        .unwrap_or_else(|| "M1 rejected the request but gave no reason".to_string());
    Err(CliError::Auth(detail))
}

/// Render whatever shape `error` arrives in: a string, `{message}`, `{code}`,
/// or a list of those.
fn describe_error(err: &Value) -> String {
    match err {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Array(items) => items
            .iter()
            .map(describe_error)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("; "),
        Value::Object(_) => {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| err.get("description").and_then(Value::as_str))
                .unwrap_or("");
            let code = err
                .get("code")
                .and_then(Value::as_str)
                .or_else(|| err.get("__typename").and_then(Value::as_str))
                .unwrap_or("");
            match (msg.is_empty(), code.is_empty()) {
                (false, false) => format!("{msg} ({code})"),
                (false, true) => msg.to_string(),
                (true, false) => code.to_string(),
                (true, true) => String::new(),
            }
        }
        other => other.to_string(),
    }
}

fn find_did_succeed(v: &Value, depth: usize) -> Option<(&Value, bool)> {
    if depth == 0 {
        return None;
    }
    if let Value::Object(map) = v {
        if let Some(flag) = map.get("didSucceed").and_then(Value::as_bool) {
            return Some((v, flag));
        }
        for (_, child) in map {
            if let Some(found) = find_did_succeed(child, depth - 1) {
                return Some(found);
            }
        }
    }
    None
}

/// Map a GraphQL `errors` array onto the family's exit codes.
///
/// M1 does not follow the Apollo convention of `extensions.code` — observed
/// live (2026-08-13), the machine-readable slug sits at the **top level** of
/// each error object, alongside an `isAuthError` boolean:
///
/// ```json
/// { "isAuthError": false, "name": "GraphQLError", "code": "GRAPHQL_VALIDATION_FAILED",
///   "http": { "status": 400 }, "message": "Cannot query field …" }
/// ```
///
/// Both spellings are read (extensions first for conventional gateways, then
/// top-level), `isAuthError: true` short-circuits to an auth failure, and
/// message sniffing remains the last resort.
pub fn classify_errors(errors: &[Value]) -> CliError {
    let message = errors
        .iter()
        .filter_map(|e| e.get("message").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("; ");
    let message = if message.is_empty() {
        "M1 returned an unspecified GraphQL error".to_string()
    } else {
        message
    };

    let codes: Vec<String> = errors
        .iter()
        .filter_map(|e| {
            e.get("extensions")
                .and_then(|x| x.get("code"))
                .and_then(Value::as_str)
                .or_else(|| e.get("code").and_then(Value::as_str))
        })
        .map(|s| s.to_ascii_uppercase())
        .collect();
    let lower = message.to_ascii_lowercase();

    let has = |needle: &str| codes.iter().any(|c| c.contains(needle));

    // An explicit machine-readable code is a contract; a message string is the
    // last resort. So EVERY code check runs before ANY message heuristic —
    // otherwise a `GRAPHQL_VALIDATION_FAILED` whose message happens to contain
    // "not found" (an unknown field, say) would be misreported as exit 4
    // instead of exit 2. `isAuthError` is M1's own top-level auth flag.
    if errors
        .iter()
        .any(|e| e.get("isAuthError").and_then(Value::as_bool) == Some(true))
    {
        return CliError::Auth(format!("{message} — try `m1f auth login`"));
    }
    if has("UNAUTHENTICATED")
        || has("UNAUTHORIZED")
        || has("FORBIDDEN")
        || has("TOKEN_EXPIRED")
        || has("INVALID_TOKEN")
    {
        return CliError::Auth(format!("{message} — try `m1f auth login`"));
    }
    if has("RATE_LIMIT") || has("TOO_MANY_REQUESTS") {
        return CliError::Upstream(format!("rate limited by M1: {message}"));
    }
    // Validation/bad-input is the caller's fault (usually a hand-written
    // document to `api query`); checked before NOT_FOUND so a validation code
    // with a "not found"-flavoured message still exits 2, not 4.
    if has("GRAPHQL_VALIDATION_FAILED") || has("BAD_USER_INPUT") || has("BAD_REQUEST") {
        return CliError::Usage(format!("M1 rejected the query: {message}"));
    }
    if has("NOT_FOUND") {
        return CliError::NotFound(message);
    }

    // No usable code: fall back to message sniffing, in the same severity order.
    if lower.contains("not authenticated")
        || lower.contains("unauthenticated")
        || lower.contains("invalid token")
        || lower.contains("token has expired")
        || lower.contains("expired token")
        || lower.contains("session expired")
    {
        return CliError::Auth(format!("{message} — try `m1f auth login`"));
    }
    if lower.contains("rate limit") {
        return CliError::Upstream(format!("rate limited by M1: {message}"));
    }
    if lower.contains("not found") {
        return CliError::NotFound(message);
    }
    CliError::Upstream(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn errs(v: Value) -> Vec<Value> {
        v.as_array().unwrap().clone()
    }

    #[test]
    fn unauthenticated_extension_code_maps_to_exit_3() {
        let e = errs(json!([{
            "message": "You must be logged in.",
            "extensions": { "code": "UNAUTHENTICATED" }
        }]));
        let err = classify_errors(&e);
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("auth login"), "{err}");
    }

    #[test]
    fn expired_token_is_detected_from_the_message_alone() {
        // Unofficial APIs often omit extensions entirely.
        let e = errs(json!([{ "message": "Session expired" }]));
        assert_eq!(classify_errors(&e).exit_code(), 3);
        let e2 = errs(json!([{ "message": "Invalid token" }]));
        assert_eq!(classify_errors(&e2).exit_code(), 3);
    }

    #[test]
    fn rate_limit_maps_to_upstream() {
        let e = errs(json!([{
            "message": "Too many requests",
            "extensions": { "code": "RATE_LIMITED" }
        }]));
        let err = classify_errors(&e);
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("rate limited"), "{err}");
    }

    #[test]
    fn not_found_maps_to_exit_4() {
        let e = errs(json!([{
            "message": "Account not found",
            "extensions": { "code": "NOT_FOUND" }
        }]));
        assert_eq!(classify_errors(&e).exit_code(), 4);
    }

    #[test]
    fn validation_failure_is_a_usage_error() {
        let e = errs(json!([{
            "message": "Cannot query field \"nope\" on type \"Account\".",
            "extensions": { "code": "GRAPHQL_VALIDATION_FAILED" }
        }]));
        assert_eq!(classify_errors(&e).exit_code(), 2);
    }

    #[test]
    fn m1s_top_level_code_and_auth_flag_are_read() {
        // The real envelope observed live: no `extensions`, code at top level.
        let e = errs(json!([{
            "isAuthError": false, "name": "GraphQLError",
            "code": "GRAPHQL_VALIDATION_FAILED",
            "http": { "status": 400 },
            "message": "Cannot query field \"nope\" on type \"Viewer\"."
        }]));
        assert_eq!(classify_errors(&e).exit_code(), 2);

        let auth = errs(json!([{
            "isAuthError": true, "name": "Error",
            "message": "signature verification failed"
        }]));
        let err = classify_errors(&auth);
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("auth login"), "{err}");
    }

    #[test]
    fn an_explicit_code_outranks_a_message_that_sniffs_otherwise() {
        // A validation error whose message contains "not found" (e.g. an
        // unknown field) must exit 2 on the code, not 4 on the message.
        let e = errs(json!([{
            "isAuthError": false,
            "code": "GRAPHQL_VALIDATION_FAILED",
            "message": "Cannot query field \"account\" — not found on type Viewer."
        }]));
        assert_eq!(classify_errors(&e).exit_code(), 2);

        // A genuine not-found *code* still maps to exit 4.
        let nf = errs(json!([{ "code": "NOT_FOUND", "message": "Account not found" }]));
        assert_eq!(classify_errors(&nf).exit_code(), 4);

        // And a message-only "not found" (no code) still maps to 4.
        let nf_msg = errs(json!([{ "message": "Account not found" }]));
        assert_eq!(classify_errors(&nf_msg).exit_code(), 4);
    }

    #[test]
    fn unknown_errors_fall_through_to_upstream() {
        let e = errs(json!([{ "message": "something odd" }]));
        let err = classify_errors(&e);
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("something odd"), "{err}");
    }

    #[test]
    fn every_message_is_surfaced_not_just_the_first() {
        let e = errs(json!([{ "message": "first" }, { "message": "second" }]));
        let err = classify_errors(&e);
        assert!(err.to_string().contains("first"), "{err}");
        assert!(err.to_string().contains("second"), "{err}");
    }

    #[test]
    fn an_error_array_with_no_messages_still_fails_loudly() {
        let e = errs(json!([{ "extensions": { "code": "WEIRD" } }]));
        let err = classify_errors(&e);
        assert_eq!(err.exit_code(), 5);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn a_failed_login_is_caught_even_though_the_envelope_is_clean() {
        // The exact trap: HTTP 200, no `errors` array, but the payload says no.
        let data = json!({
            "authenticate": {
                "didSucceed": false,
                "error": { "message": "Invalid username or password", "code": "BAD_CREDENTIALS" },
                "outcome": null
            }
        });
        let err = check_did_succeed(&data).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("Invalid username"), "{err}");
        assert!(err.to_string().contains("BAD_CREDENTIALS"), "{err}");
    }

    #[test]
    fn a_successful_payload_passes_through() {
        let data = json!({
            "authenticate": { "didSucceed": true, "outcome": { "accessToken": "a" } }
        });
        assert!(check_did_succeed(&data).is_ok());
    }

    #[test]
    fn a_payload_without_the_flag_is_not_second_guessed() {
        assert!(check_did_succeed(&json!({ "viewer": { "id": "1" } })).is_ok());
    }

    #[test]
    fn a_failure_with_no_error_detail_still_fails() {
        let data = json!({ "authenticate": { "didSucceed": false } });
        let err = check_did_succeed(&data).unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains("gave no reason"), "{err}");
    }

    #[test]
    fn error_detail_renders_from_string_object_or_list() {
        assert_eq!(describe_error(&json!("boom")), "boom");
        assert_eq!(describe_error(&json!({ "message": "m" })), "m");
        assert_eq!(describe_error(&json!({ "code": "C" })), "C");
        assert_eq!(
            describe_error(&json!([{ "message": "a" }, { "message": "b" }])),
            "a; b"
        );
        assert_eq!(describe_error(&Value::Null), "");
    }

    #[test]
    fn scrub_masks_account_numbers_and_blobs_but_keeps_diagnostics() {
        // An 8+ digit run (account number) is masked.
        assert_eq!(
            scrub("Account 12345678 not found"),
            "Account <redacted> not found"
        );
        // A short number (a line/column, a small id) survives.
        assert_eq!(scrub("line 12 column 5"), "line 12 column 5");
        // A long base64-ish token (an id blob) is masked.
        let blob = "SW52ZXN0QWNjb3VudERvY3VtZW50OnsiZG9jdW1lbnQi";
        assert_eq!(scrub(&format!("bad id {blob}")), "bad id <redacted>");
        // A normal schema-discovery message is untouched.
        assert_eq!(
            scrub("Cannot query field \"nope\" on type Viewer."),
            "Cannot query field \"nope\" on type Viewer."
        );
    }

    /// The gap the reviewer caught: a digit run GLUED to a token prefix (so it
    /// sits inside a tokenish span shorter than 24) must still be masked.
    #[test]
    fn scrub_masks_digit_runs_glued_to_a_token_prefix() {
        assert_eq!(scrub("accountId=5551234567"), "accountId=<redacted>");
        assert_eq!(scrub("acct-5551234567"), "acct-<redacted>");
        // A short id blob (under the 24-char token threshold) that still ends
        // in a long digit run is masked digit-side.
        assert_eq!(scrub("id:abc12345678"), "id:abc<redacted>");
    }

    /// The over-masking direction: a long *identifier* (no digit, no base64
    /// special) is the token the verbose dump exists to surface on schema
    /// drift, so it must survive even past 24 chars.
    #[test]
    fn scrub_keeps_long_identifiers_the_dump_exists_to_show() {
        // Exactly 24 chars, all letters — a field name this CLI selects.
        assert_eq!(
            scrub("Cannot query field \"disallowedWashSaleAmount\" on type TaxLot"),
            "Cannot query field \"disallowedWashSaleAmount\" on type TaxLot"
        );
        // 31 chars, a type name.
        assert_eq!(
            scrub("no fragment on InvestActivityTradeSummaryEntry"),
            "no fragment on InvestActivityTradeSummaryEntry"
        );
        // A SCREAMING_SNAKE code in the message survives too.
        assert_eq!(
            scrub("code GRAPHQL_VALIDATION_FAILED here"),
            "code GRAPHQL_VALIDATION_FAILED here"
        );
        // But a blob-shaped 24+ run (has digits) is still masked.
        assert_eq!(
            scrub("blob aGVsbG8xMjM0NTY3ODkwYWJjZGVm here"),
            "blob <redacted> here"
        );
    }

    #[test]
    fn redact_errors_drops_unknown_fields_and_scrubs_the_message() {
        let errors = errs(json!([{
            "isAuthError": false,
            "name": "GraphQLError",
            "code": "NOT_FOUND",
            "message": "Account 5551234567 not found",
            "path": ["viewer", "accounts"],
            "extensions": { "code": "NOT_FOUND", "accountNumber": "5551234567" }
        }]));
        let out = redact_errors(&errors);
        // The account number is gone from both message and extensions.
        assert!(!out.contains("5551234567"), "account number leaked: {out}");
        // The raw `extensions` object (with accountNumber) is dropped; only
        // extensions.code is surfaced.
        assert!(out.contains("NOT_FOUND"));
        assert!(out.contains("viewer"));
        assert!(out.contains("<redacted>"));
    }

    #[test]
    fn an_html_answer_points_at_the_browser_session_login() {
        let read = html_error(reqwest::StatusCode::FORBIDDEN);
        assert_eq!(read.exit_code(), 3);
        assert!(
            read.to_string()
                .contains("`m1f auth login --browser --overwrite`"),
            "{read}"
        );
        let login = legacy_login_blocked(reqwest::StatusCode::FORBIDDEN);
        assert_eq!(login.exit_code(), 3);
        let msg = login.to_string();
        assert!(msg.contains("403"), "{msg}");
        assert!(msg.contains("`m1f auth login --browser`"), "{msg}");
        assert!(msg.contains("nothing was stored"), "{msg}");
    }

    #[test]
    fn a_bundle_without_the_auth0_marker_reads_as_legacy() {
        let legacy: TokenBundle =
            serde_json::from_str(r#"{"access_token":"a","refresh_token":"r"}"#).unwrap();
        assert!(legacy.auth0.is_none());
        assert_eq!(legacy.login_hint(), "m1f auth login");
        let stored = serde_json::to_string(&legacy).unwrap();
        assert!(!stored.contains("auth0"), "{stored}");
        let browser = TokenBundle {
            auth0: Some(crate::auth0::Auth0Grant::default()),
            ..legacy
        };
        assert_eq!(browser.login_hint(), "m1f auth login --browser --overwrite");
        let round: TokenBundle =
            serde_json::from_str(&serde_json::to_string(&browser).unwrap()).unwrap();
        assert_eq!(round.auth0, browser.auth0);
    }

    #[test]
    fn html_detection_catches_login_redirects() {
        assert!(looks_like_html(
            "<!DOCTYPE html><html><body>login</body></html>"
        ));
        assert!(looks_like_html("  <html lang=\"en\">"));
        assert!(!looks_like_html(r#"{"data":{}}"#));
    }
}
