//! M1's Auth0 session — the login M1's own web app uses.
//!
//! # Why this exists
//!
//! On 2026-10-27 the legacy password login (`Authenticate` mutation) began
//! answering **HTTP 403 with a Cloudflare HTML page**, while the
//! unauthenticated `system` probe still answered `NORMAL`. M1's web
//! dashboard no longer sends that mutation at all: its bundle (read the same
//! day, `dashboard.m1.com/assets/index-*.js`) signs in through Auth0 with
//! `@auth0/auth0-spa-js`, configured as
//!
//! | Setting | Value |
//! | --- | --- |
//! | domain | `account.m1.com` (`/.well-known/openid-configuration` answers there) |
//! | clientId | [`CLIENT_ID`] — a public SPA client, printed in the bundle |
//! | audience | [`AUDIENCE`] |
//! | scope | `openid profile email offline_access exchange:exchange:read` |
//! | cacheLocation | `localstorage` |
//! | useRefreshTokens | `true` |
//!
//! and its Apollo link sends `Authorization: Bearer <getTokenSilently()>` —
//! the Auth0 access token — to the same `https://lens.m1.com/graphql`. So a
//! session captured from a logged-in browser is exactly what the GraphQL
//! endpoint accepts.
//!
//! # What is captured
//!
//! auth0-spa-js keeps its token cache in the dashboard's localStorage under
//! `@@auth0spajs@@::<clientId>::<audience>::<scope>`; the value is
//! `{"body": {"access_token", "refresh_token", "expires_in", "audience",
//! "client_id", "scope", "id_token", …}, "expiresAt": <epoch seconds>}`.
//! `auth login --browser` reads that value out of a Chrome window the owner
//! signs in through ([`browser_capture`]); the fallback is the owner copying
//! it out of DevTools and piping it to `auth login --browser-session --stdin`.
//! Both land in one reader ([`parse_browser_capture`] and [`parse_captured`]
//! differ only in how a refusal is reported), which reads that value, the
//! whole localStorage map (`JSON.stringify(localStorage)`), an Auth0 token
//! response, or a bare `Bearer <token>` copied from a request's headers. Only the access
//! token, the refresh token, the expiry and the client id are kept; the id
//! token and the decoded profile it carries are dropped.
//!
//! # Renewal
//!
//! With a refresh token the CLI renews its own access token at the tenant's
//! token endpoint ([`refresh`]) — the `refresh_token` grant a public client
//! may use with no secret (`token_endpoint_auth_methods_supported` lists
//! `none`). auth0-spa-js asks for refresh tokens, and an Auth0 tenant
//! normally rotates them: each renewal returns a new one and retires the old.
//! Two holders of one refresh token therefore race, and Auth0 answers reuse of
//! a retired token by revoking the whole family. So the CLI must end up the
//! only holder: `auth login --browser` closes the dashboard tab the moment the
//! session is read and then quits Chrome, and the DevTools steps have the owner
//! sign in in a private window and close it after copying. The profile `--browser`
//! keeps holds no copy between runs: its site storage goes around every launch
//! (docs/api.md, "The kept profile"). Whether M1's tenant rotates, and how long
//! its access tokens live, has not been observed (docs/api.md, "What is still
//! unverified").

use pk_cli_browser::{Capture, HostRule};
use pk_cli_core::CliError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::TokenBundle;

/// M1's Auth0 tenant (its custom domain).
pub const DOMAIN: &str = "account.m1.com";

/// The dashboard's Auth0 SPA client id — public, printed in M1's web bundle.
pub const CLIENT_ID: &str = "1Gz7GHj4BiQ9lTQgVpleNuzUHl2KQnYI";

/// The API audience the dashboard's access tokens are minted for.
pub const AUDIENCE: &str = "https://lens.m1finance.com";

/// auth0-spa-js's localStorage key prefix.
pub const CACHE_KEY_PREFIX: &str = "@@auth0spajs@@::";

/// The login that works: the session captured from a browser sign-in.
pub const LOGIN: &str = "m1f auth login --browser";

/// The same login when a session is already stored, which `auth login`
/// replaces only with `--overwrite`.
pub const RELOGIN: &str = "m1f auth login --browser --overwrite";

/// The fallback without Chrome: the session copied out of DevTools and piped
/// in (steps in `m1f auth login --help`).
pub const STDIN_LOGIN: &str = "m1f auth login --browser-session --stdin";

/// The host M1's web app keeps the session on, and the only host
/// `auth login --browser` reads from. Its sign-in page is on Auth0's host
/// (`account.m1.com`), which the capture never touches.
pub const DASHBOARD_HOST: &str = "dashboard.m1.com";

/// What `auth login --browser` evaluates in dashboard.m1.com pages: the value
/// of auth0-spa-js's cache entry for M1's API (the key that starts with
/// [`CACHE_KEY_PREFIX`] and names [`AUDIENCE`]'s host) once it holds an access
/// token, and `null` before, while the owner is still signing in. It is the
/// value the DevTools snippet in `auth login --help` copies, so the one reader
/// takes both ([`parse_browser_capture`], [`parse_captured`]). docs/api.md
/// quotes it verbatim.
///
/// It only reads: the launch clears the profile's site storage
/// (`commands::auth::browser_launch`). Whether what it reads is worth taking is the
/// confirm hook's call (`commands::auth::confirm_candidate`).
pub const CAPTURE_EXPRESSION: &str = "(() => { const k = Object.keys(localStorage).find(k => \
     k.startsWith('@@auth0spajs@@::') && k.includes('lens.m1finance.com')); const v = k && \
     localStorage[k]; return v && v.includes('access_token') ? v : null; })()";

/// The `auth login --browser` capture: [`CAPTURE_EXPRESSION`], read only from
/// pages on exactly [`DASHBOARD_HOST`].
pub fn browser_capture() -> Result<Capture, CliError> {
    Ok(Capture::new("M1", HostRule::exact(DASHBOARD_HOST)?)
        .expression(CAPTURE_EXPRESSION)
        .hint("password and any emailed code"))
}

/// What renews an Auth0 bundle: the client its refresh token was issued to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Auth0Grant {
    pub client_id: String,
}

impl Default for Auth0Grant {
    fn default() -> Self {
        Auth0Grant {
            client_id: CLIENT_ID.to_string(),
        }
    }
}

/// Why the reader refused a session. `what` says what is wrong with it, in
/// words true of either route; `fix` is the paste route's advice (what to copy
/// instead), which the browser route leaves out, since nothing was pasted.
#[derive(Debug)]
struct Refusal {
    what: String,
    fix: &'static str,
}

impl Refusal {
    fn new(what: impl Into<String>, fix: &'static str) -> Self {
        Refusal {
            what: what.into(),
            fix,
        }
    }
}

/// The paste route's advice for a value that is not the session.
const COPY_WITH_SNIPPET: &str = "copy it with the DevTools snippet in `m1f auth login --help` \
                                 and pipe it in with `pbpaste | m1f auth login \
                                 --browser-session --stdin` (a terminal paste can cut a long \
                                 value short)";

/// The paste route's advice for a session that is not M1's API's.
const COPY_M1_ENTRY: &str = "copy the localStorage entry whose key contains \
                             `lens.m1finance.com` (the DevTools snippet in `m1f auth login \
                             --help` does)";

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn str_at<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Read a pasted browser session into a token bundle (see the module doc
/// for the shapes accepted). Every rejection is a usage error naming what to
/// copy instead; nothing about the pasted value is echoed.
pub fn parse_captured(raw: &str) -> Result<TokenBundle, CliError> {
    read_session(raw).map_err(|r| CliError::Usage(format!("{} — {}", r.what, r.fix)))
}

/// Read the session `auth login --browser` captured, with the same reader
/// as [`parse_captured`]. A refusal here is not the owner's mis-copy but M1
/// changing how its web app keeps the session, so it is exit 5, and it names
/// what was wrong without the paste route's advice.
pub fn parse_browser_capture(raw: &str) -> Result<TokenBundle, CliError> {
    read_session(raw).map_err(|r| {
        CliError::Upstream(format!(
            "the session read from {DASHBOARD_HOST} is not one m1f can use: {}. M1 may have \
             changed how its web app keeps it (docs/api.md). Nothing was stored.",
            r.what
        ))
    })
}

/// The one reader both routes share.
fn read_session(raw: &str) -> Result<TokenBundle, Refusal> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Refusal::new(
            "the session is empty",
            "pipe the copied value in (see `m1f auth login --help`)",
        ));
    }
    if raw.starts_with('{') {
        let v: Value = serde_json::from_str(raw).map_err(|e| {
            Refusal::new(
                format!("the session is not valid JSON ({e})"),
                COPY_WITH_SNIPPET,
            )
        })?;
        return from_json(&v, None);
    }
    bare_token(raw)
}

/// A bare access token, as a request's `Authorization` header carries it.
/// It works until it expires; with no refresh token the CLI cannot renew it.
fn bare_token(raw: &str) -> Result<TokenBundle, Refusal> {
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .unwrap_or(raw)
        .trim();
    // A bearer token is base64url segments joined by dots (RFC 6750's
    // token68 alphabet); anything else is a mis-copy.
    let token68 = |c: char| c.is_ascii_alphanumeric() || "-._~+/=".contains(c);
    if token.is_empty() || !token.chars().all(token68) {
        return Err(Refusal::new(
            "the value is neither the session JSON nor a single bearer token",
            COPY_WITH_SNIPPET,
        ));
    }
    check_claims(token)?;
    Ok(bundle(token, None, None, None))
}

/// One of the JSON shapes: a cache entry, a token response, or a
/// localStorage map holding a cache entry.
fn from_json(v: &Value, key: Option<&str>) -> Result<TokenBundle, Refusal> {
    // auth0-spa-js's cache entry: `{ body: { access_token, … }, expiresAt }`.
    if let Some(body) = v.get("body").filter(|b| b.get("access_token").is_some()) {
        return from_token_object(body, v.get("expiresAt").and_then(Value::as_i64), key);
    }
    // A token response (or the body alone).
    if v.get("access_token").is_some() {
        return from_token_object(v, None, key);
    }
    // The localStorage map: the entry for M1's API among auth0-spa-js's keys.
    let Some(map) = v.as_object() else {
        return Err(Refusal::new(
            "the session JSON is not an object",
            COPY_WITH_SNIPPET,
        ));
    };
    let mut found: Vec<(i64, TokenBundle)> = Vec::new();
    let mut other_audiences = 0usize;
    for (k, val) in map {
        if !k.starts_with(CACHE_KEY_PREFIX) {
            continue;
        }
        // localStorage values are strings; a hand-built map may nest objects.
        let entry = match val {
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(e) => e,
                Err(_) => continue,
            },
            Value::Object(_) => val.clone(),
            _ => continue,
        };
        let Some(body) = entry
            .get("body")
            .filter(|b| b.get("access_token").is_some())
        else {
            continue;
        };
        let audience = str_at(body, "audience").or_else(|| key_audience(k));
        if audience.is_some_and(|a| a != AUDIENCE) {
            other_audiences += 1;
            continue;
        }
        let expires = entry.get("expiresAt").and_then(Value::as_i64).unwrap_or(0);
        found.push((expires, from_token_object(body, Some(expires), Some(k))?));
    }
    // Several entries (one per scope set) are the same session; the latest
    // expiry is the freshest token.
    found.sort_by_key(|(expires, _)| *expires);
    found.pop().map(|(_, b)| b).ok_or_else(|| {
        Refusal::new(
            format!(
                "the value holds no Auth0 session for M1's API ({AUDIENCE}){}",
                if other_audiences > 0 {
                    format!(" ({other_audiences} entry/entries for another audience)")
                } else {
                    String::new()
                }
            ),
            "sign in at https://dashboard.m1.com first, then copy with the DevTools snippet in \
             `m1f auth login --help`",
        )
    })
}

/// The audience segment of a `@@auth0spajs@@::<clientId>::<audience>::<scope>`
/// key.
fn key_audience(key: &str) -> Option<&str> {
    key.strip_prefix(CACHE_KEY_PREFIX)?.split("::").nth(1)
}

/// The client-id segment of the same key.
fn key_client(key: &str) -> Option<&str> {
    key.strip_prefix(CACHE_KEY_PREFIX)?
        .split("::")
        .next()
        .filter(|s| !s.is_empty() && *s != "@@user@@")
}

fn from_token_object(
    body: &Value,
    expires_at: Option<i64>,
    key: Option<&str>,
) -> Result<TokenBundle, Refusal> {
    let access = str_at(body, "access_token").ok_or_else(|| {
        Refusal::new(
            "the session has no `access_token`",
            "copy the whole cache entry",
        )
    })?;
    if let Some(aud) = str_at(body, "audience") {
        if aud != AUDIENCE {
            return Err(Refusal::new(
                format!("the session is for `{aud}`, not M1's API ({AUDIENCE})"),
                COPY_M1_ENTRY,
            ));
        }
    }
    let claims = check_claims(access)?;
    let client_id = str_at(body, "client_id")
        .or_else(|| key.and_then(key_client))
        .or_else(|| claims.as_ref().and_then(|c| str_at(c, "azp")))
        .map(str::to_string);
    let expires_at = expires_at
        .filter(|e| *e > 0)
        .or_else(|| {
            body.get("expires_in")
                .and_then(Value::as_i64)
                .map(|s| now_secs() + s)
        })
        .map(pk_cli_core::dates::fmt_rfc3339);
    Ok(bundle(
        access,
        str_at(body, "refresh_token"),
        expires_at,
        client_id,
    ))
}

/// Read what a JWT access token says about itself — not to trust it (the
/// server is the authority, `pk_cli_auth::token`), but to refuse a token
/// minted for some other API or tenant before it is stored. A token that is
/// not a readable JWT passes: the verification read decides.
fn check_claims(token: &str) -> Result<Option<Value>, Refusal> {
    let Some(claims) = pk_cli_auth::token::claims(token) else {
        return Ok(None);
    };
    let aud_ok = match claims.get("aud") {
        None => true,
        Some(Value::String(a)) => a == AUDIENCE,
        Some(Value::Array(list)) => list.iter().any(|a| a.as_str() == Some(AUDIENCE)),
        Some(_) => false,
    };
    if !aud_ok {
        return Err(Refusal::new(
            format!("the token is not for M1's API (its audience is not {AUDIENCE})"),
            COPY_M1_ENTRY,
        ));
    }
    if let Some(iss) = str_at(&claims, "iss") {
        let host = iss
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string();
        if host != DOMAIN {
            return Err(Refusal::new(
                format!("the token was issued by `{host}`, not M1's sign-in service ({DOMAIN})"),
                "sign in at https://dashboard.m1.com and copy the session from there",
            ));
        }
    }
    Ok(Some(claims))
}

fn bundle(
    access: &str,
    refresh: Option<&str>,
    expires_at: Option<String>,
    client_id: Option<String>,
) -> TokenBundle {
    TokenBundle {
        access_token: access.to_string(),
        refresh_token: refresh.map(str::to_string),
        // The token's own `exp` is the authority when it has one.
        expires_at: pk_cli_auth::token::expires_at(access).or(expires_at),
        auth0: Some(Auth0Grant {
            client_id: client_id.unwrap_or_else(|| CLIENT_ID.to_string()),
        }),
    }
}

/// Renew an Auth0 bundle with its refresh token.
///
/// The tenant's `refresh_token` grant, as auth0-spa-js sends it from the
/// dashboard (form-encoded, `Origin` the dashboard's). Rotation is honoured:
/// a new refresh token replaces the old, and without one the old is kept.
pub fn refresh(
    grant: &Auth0Grant,
    refresh_token: &str,
    verbose: bool,
) -> Result<TokenBundle, CliError> {
    let url = format!("https://{DOMAIN}/oauth/token");
    if verbose {
        eprintln!("POST {url} (refresh_token grant)");
    }
    let http = pk_cli_http::client("m1f", env!("CARGO_PKG_VERSION"))?;
    let resp = http
        .post(&url)
        .header("accept", "application/json")
        .header("origin", crate::client::WEB_ORIGIN)
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", grant.client_id.as_str()),
            ("refresh_token", refresh_token),
        ])
        .send()?;
    let status = resp.status().as_u16();
    let text = resp.text()?;
    token_response(status, &text, grant, refresh_token)
}

/// The fix every refusal of a stored session points at.
pub const RECAPTURE: &str = "sign in again: `m1f auth login --browser --overwrite` (without \
                             Chrome, the DevTools steps in `m1f auth login --help`)";

/// Classify the token endpoint's answer. Pure, so every branch is tested
/// offline.
fn token_response(
    status: u16,
    body: &str,
    grant: &Auth0Grant,
    old_refresh: &str,
) -> Result<TokenBundle, CliError> {
    let Ok(v) = serde_json::from_str::<Value>(body) else {
        return Err(CliError::Upstream(
            if crate::client::looks_like_html(body) {
                format!(
                    "M1's sign-in service answered the token refresh with an HTML page (HTTP \
                 {status}) — a bot check stood in the way; retry later, or {RECAPTURE}"
                )
            } else {
                format!("unparseable answer from M1's sign-in service (HTTP {status})")
            },
        ));
    };
    if (200..300).contains(&status) {
        let Some(access) = str_at(&v, "access_token") else {
            return Err(CliError::Upstream(
                "M1's sign-in service renewed the session but returned no access token".into(),
            ));
        };
        let expires = v
            .get("expires_in")
            .and_then(Value::as_i64)
            .map(|s| pk_cli_core::dates::fmt_rfc3339(now_secs() + s));
        return Ok(bundle(
            access,
            Some(str_at(&v, "refresh_token").unwrap_or(old_refresh)),
            expires,
            Some(grant.client_id.clone()),
        ));
    }
    let code = str_at(&v, "error").unwrap_or("unknown_error");
    let detail = str_at(&v, "error_description").unwrap_or("");
    let what = if detail.is_empty() {
        code.to_string()
    } else {
        format!("{code}: {detail}")
    };
    Err(match (status, code) {
        (429, _) => CliError::Upstream(format!(
            "M1's sign-in service is rate limiting token refreshes ({what}) — wait before \
             retrying"
        )),
        (_, "invalid_grant") => CliError::Auth(format!(
            "M1 refused the stored refresh token ({what}) — the browser session ended, or the \
             token was used elsewhere after the CLI rotated it; {RECAPTURE}"
        )),
        (400..=499, _) => CliError::Auth(format!(
            "M1's sign-in service refused the token refresh (HTTP {status}, {what}); \
             {RECAPTURE}"
        )),
        _ => CliError::Upstream(format!(
            "M1's sign-in service failed the token refresh (HTTP {status}, {what})"
        )),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    /// A JWT-shaped dummy with the given claims and a fake signature. Built
    /// at test time so no token-shaped literal sits in the source.
    pub(crate) fn jwt(claims: Value) -> String {
        fn b64(bytes: &[u8]) -> String {
            const T: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let b = [
                    chunk[0],
                    *chunk.get(1).unwrap_or(&0),
                    *chunk.get(2).unwrap_or(&0),
                ];
                let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
                let chars = [18, 12, 6, 0].map(|s| T[((n >> s) & 63) as usize] as char);
                out.extend(&chars[..chunk.len() + 1]);
            }
            out
        }
        format!(
            "{}.{}.DUMMYSIG",
            b64(br#"{"alg":"RS256","typ":"JWT"}"#),
            b64(claims.to_string().as_bytes())
        )
    }

    pub(crate) fn m1_claims(exp: i64) -> Value {
        json!({
            "iss": "https://account.m1.com/",
            "aud": [AUDIENCE, "https://account.m1.com/userinfo"],
            "azp": CLIENT_ID,
            "exp": exp
        })
    }

    pub(crate) fn cache_entry(access: &str) -> Value {
        json!({
            "body": {
                "access_token": access,
                "refresh_token": "DUMMY.REFRESH.TOKEN",
                "id_token": "DUMMY.ID.TOKEN",
                "scope": "openid profile email offline_access exchange:exchange:read",
                "expires_in": 86400,
                "token_type": "Bearer",
                "audience": AUDIENCE,
                "client_id": CLIENT_ID,
                "decodedToken": { "user": { "email": "owner@example.invalid" } }
            },
            "expiresAt": 1_900_000_000
        })
    }

    fn cache_key() -> String {
        format!(
            "{CACHE_KEY_PREFIX}{CLIENT_ID}::{AUDIENCE}::openid profile email offline_access \
             exchange:exchange:read"
        )
    }

    #[test]
    fn the_spa_cache_entry_reads_into_an_auth0_bundle() {
        let token = jwt(m1_claims(1_900_000_000));
        let b = parse_captured(&cache_entry(&token).to_string()).unwrap();
        assert_eq!(b.access_token, token);
        assert_eq!(b.refresh_token.as_deref(), Some("DUMMY.REFRESH.TOKEN"));
        assert_eq!(b.expires_at.as_deref(), Some("2030-03-17T17:46:40Z"));
        assert_eq!(b.auth0, Some(Auth0Grant::default()));
        // Only what renews the session is kept: no id token, no profile.
        let stored = serde_json::to_string(&b).unwrap();
        assert!(!stored.contains("ID.TOKEN"), "{stored}");
        assert!(!stored.contains("example.invalid"), "{stored}");
    }

    #[test]
    fn the_whole_localstorage_map_finds_m1s_entry() {
        let token = jwt(m1_claims(1_900_000_000));
        let map = json!({
            "ajs_anonymous_id": "\"abc\"",
            (format!("{CACHE_KEY_PREFIX}{CLIENT_ID}::@@user@@")): "{\"id_token\":\"DUMMY.ID.TOKEN\"}",
            (cache_key()): cache_entry(&token).to_string(),
        });
        let b = parse_captured(&map.to_string()).unwrap();
        assert_eq!(b.access_token, token);
        assert_eq!(b.refresh_token.as_deref(), Some("DUMMY.REFRESH.TOKEN"));
    }

    #[test]
    fn of_several_entries_the_latest_expiry_wins() {
        let old = jwt(m1_claims(1_800_000_000));
        let new = jwt(m1_claims(1_900_000_000));
        let mut older = cache_entry(&old);
        older["expiresAt"] = json!(1_800_000_000);
        let map = json!({
            (cache_key()): cache_entry(&new).to_string(),
            (format!("{}::openid", cache_key())): older.to_string(),
        });
        assert_eq!(parse_captured(&map.to_string()).unwrap().access_token, new);
    }

    #[test]
    fn a_map_without_m1s_entry_says_what_to_copy() {
        let err = parse_captured(&json!({ "theme": "dark" }).to_string()).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("dashboard.m1.com"), "{err}");
    }

    #[test]
    fn an_entry_for_another_audience_is_refused() {
        let mut e = cache_entry(&jwt(m1_claims(1_900_000_000)));
        e["body"]["audience"] = json!("https://other.example.invalid");
        let err = parse_captured(&e.to_string()).unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("lens.m1finance.com"), "{err}");
    }

    #[test]
    fn a_token_for_another_api_or_tenant_is_refused() {
        let mut claims = m1_claims(1_900_000_000);
        claims["aud"] = json!("https://other.example.invalid");
        assert_eq!(parse_captured(&jwt(claims)).unwrap_err().exit_code(), 2);
        let mut claims = m1_claims(1_900_000_000);
        claims["iss"] = json!("https://evil.example.invalid/");
        let err = parse_captured(&jwt(claims)).unwrap_err();
        assert!(err.to_string().contains("evil.example.invalid"), "{err}");
    }

    #[test]
    fn a_bare_bearer_header_is_an_access_token_without_renewal() {
        let token = jwt(m1_claims(1_900_000_000));
        let b = parse_captured(&format!("Bearer {token}\n")).unwrap();
        assert_eq!(b.access_token, token);
        assert!(b.refresh_token.is_none());
        assert_eq!(b.expires_at.as_deref(), Some("2030-03-17T17:46:40Z"));
        assert!(b.auth0.is_some());
    }

    #[test]
    fn junk_is_a_usage_error() {
        assert_eq!(parse_captured("").unwrap_err().exit_code(), 2);
        assert_eq!(parse_captured("two words").unwrap_err().exit_code(), 2);
        assert_eq!(parse_captured("{not json").unwrap_err().exit_code(), 2);
        assert_eq!(parse_captured("[1,2]").unwrap_err().exit_code(), 2);
    }

    /// The synthetic fixture (tests/fixtures/auth) is the shape the reader is
    /// held to: the token pair, the client and the absolute expiry come out;
    /// the id token and its decoded claims do not.
    #[test]
    fn the_fixture_cache_entry_reads() {
        let raw = include_str!("../tests/fixtures/auth/auth0-spa-cache.json");
        let b = parse_captured(raw).unwrap();
        assert_eq!(b.access_token, "DUMMY.ACCESS.TOKEN");
        assert_eq!(b.refresh_token.as_deref(), Some("DUMMY.REFRESH.TOKEN"));
        assert_eq!(b.expires_at.as_deref(), Some("2030-03-17T17:46:40Z"));
        assert_eq!(b.auth0, Some(Auth0Grant::default()));
        let stored = serde_json::to_string(&b).unwrap();
        assert!(!stored.contains("ID.TOKEN") && !stored.contains("DUMMYSUBJECT"));
        // The same entry inside a localStorage map, as `JSON.stringify(localStorage)`
        // copies it.
        let map = json!({ (cache_key()): raw });
        assert_eq!(parse_captured(&map.to_string()).unwrap(), b);
    }

    /// The browser capture reads, on exactly the dashboard's host, the value
    /// the reader takes: the cache entry under the prefix [`parse_captured`]
    /// looks for, for the audience it accepts, gated on the access token the
    /// reader requires.
    #[test]
    fn the_browser_capture_reads_what_the_session_reader_takes() {
        let capture = browser_capture().unwrap();
        capture.validate().unwrap();
        let host = HostRule::exact(DASHBOARD_HOST).unwrap();
        assert!(host.matches_url(crate::client::WEB_ORIGIN), "launch URL");
        assert!(host.matches_url("https://dashboard.m1.com/d/invest"));
        for elsewhere in [
            "https://account.m1.com/u/login",
            "https://m1.com/",
            "http://dashboard.m1.com/",
            "https://dashboard.m1.com.example.invalid/",
        ] {
            assert!(!host.matches_url(elsewhere), "{elsewhere}");
        }
        let audience_host = AUDIENCE.strip_prefix("https://").unwrap();
        for needle in [
            format!("k.startsWith('{CACHE_KEY_PREFIX}')"),
            format!("k.includes('{audience_host}')"),
            "v.includes('access_token') ? v : null".to_string(),
        ] {
            assert!(CAPTURE_EXPRESSION.contains(&needle), "{needle}");
        }
        // It only reads: the launch clears the profile's site storage.
        for write in ["removeItem", "setItem", ".clear("] {
            assert!(!CAPTURE_EXPRESSION.contains(write), "{write}");
        }

        // What the expression hands back is the entry's stored string, here
        // the synthetic fixture: it carries the readiness signal, and the
        // stdin path's reader turns it into the same bundle a paste would.
        let captured = include_str!("../tests/fixtures/auth/auth0-spa-cache.json");
        assert!(captured.contains("access_token"));
        let compact = serde_json::from_str::<Value>(captured).unwrap().to_string();
        let b = parse_browser_capture(&compact).unwrap();
        assert_eq!(b, parse_captured(captured).unwrap());
        assert_eq!(b.access_token, "DUMMY.ACCESS.TOKEN");
        assert_eq!(b.refresh_token.as_deref(), Some("DUMMY.REFRESH.TOKEN"));
        assert_eq!(b.auth0, Some(Auth0Grant::default()));
    }

    /// One reader, two framings: a value the reader refuses is the paster's
    /// exit 2 with what to copy, and on the browser route M1's exit 5 naming
    /// the host and what was wrong, with no paste advice (nothing was pasted).
    #[test]
    fn a_refusal_reads_per_route() {
        let mut other_audience = cache_entry(&jwt(m1_claims(1_900_000_000)));
        other_audience["body"]["audience"] = json!("https://other.example.invalid");
        let mut other_aud = m1_claims(1_900_000_000);
        other_aud["aud"] = json!("https://other.example.invalid");
        let mut other_iss = m1_claims(1_900_000_000);
        other_iss["iss"] = json!("https://evil.example.invalid/");
        let refused = [
            String::new(),
            "two words".into(),
            "{not json".into(),
            "[1,2]".into(),
            r#"{"theme":"dark"}"#.into(),
            json!({ "body": { "access_token": "" } }).to_string(),
            other_audience.to_string(),
            jwt(other_aud),
            jwt(other_iss),
        ];
        for raw in &refused {
            let pasted = parse_captured(raw).unwrap_err();
            assert_eq!(pasted.exit_code(), 2, "{raw}: {pasted}");
            let captured = parse_browser_capture(raw).unwrap_err();
            let msg = captured.to_string();
            assert_eq!(captured.exit_code(), 5, "{raw}: {msg}");
            assert!(msg.contains(DASHBOARD_HOST), "{msg}");
            assert!(msg.contains("Nothing was stored"), "{msg}");
            for advice in ["paste", "pipe", "copy", "DevTools", "--browser-session"] {
                assert!(!msg.contains(advice), "{advice:?} in {msg}");
            }
            // The reason is the same words on both routes.
            let what = msg
                .split_once("can use: ")
                .and_then(|(_, rest)| rest.split_once(". M1 may"))
                .map(|(what, _)| what)
                .unwrap();
            assert!(pasted.to_string().starts_with(what), "{pasted} / {what}");
        }
    }

    /// docs/api.md records the capture verbatim, so the two cannot drift.
    #[test]
    fn docs_quote_the_capture_expression() {
        let api = include_str!("../docs/api.md");
        assert!(api.contains(CAPTURE_EXPRESSION), "docs/api.md");
        assert!(api.contains(DASHBOARD_HOST), "docs/api.md");
    }

    #[test]
    fn the_recapture_hint_is_the_relogin() {
        assert!(RECAPTURE.contains(&format!("`{RELOGIN}`")), "{RECAPTURE}");
        assert!(RELOGIN.starts_with(LOGIN));
    }

    #[test]
    fn the_key_segments_are_read() {
        assert_eq!(key_audience(&cache_key()), Some(AUDIENCE));
        assert_eq!(key_client(&cache_key()), Some(CLIENT_ID));
        assert_eq!(
            key_client(&format!("{CACHE_KEY_PREFIX}@@user@@")),
            None,
            "the user entry names no client"
        );
    }

    #[test]
    fn a_renewal_keeps_the_rotated_refresh_token() {
        let token = jwt(m1_claims(1_900_000_000));
        let body = json!({
            "access_token": token,
            "refresh_token": "DUMMY.REFRESH.ROTATED",
            "expires_in": 86400,
            "token_type": "Bearer"
        });
        let b =
            token_response(200, &body.to_string(), &Auth0Grant::default(), "DUMMY.OLD").unwrap();
        assert_eq!(b.refresh_token.as_deref(), Some("DUMMY.REFRESH.ROTATED"));
        assert_eq!(b.auth0, Some(Auth0Grant::default()));
    }

    #[test]
    fn a_renewal_without_rotation_keeps_the_old_refresh_token() {
        let body = json!({ "access_token": jwt(m1_claims(1_900_000_000)), "expires_in": 60 });
        let b =
            token_response(200, &body.to_string(), &Auth0Grant::default(), "DUMMY.OLD").unwrap();
        assert_eq!(b.refresh_token.as_deref(), Some("DUMMY.OLD"));
    }

    #[test]
    fn a_dead_refresh_token_is_an_auth_failure_naming_the_recapture() {
        let body = json!({
            "error": "invalid_grant",
            "error_description": "Unknown or invalid refresh token."
        });
        let err = token_response(403, &body.to_string(), &Auth0Grant::default(), "x").unwrap_err();
        assert_eq!(err.exit_code(), 3);
        assert!(err.to_string().contains(&format!("`{RELOGIN}`")), "{err}");
    }

    #[test]
    fn rate_limits_html_and_server_errors_are_upstream() {
        let g = Auth0Grant::default();
        let limited = json!({ "error": "too_many_requests" }).to_string();
        assert_eq!(
            token_response(429, &limited, &g, "x")
                .unwrap_err()
                .exit_code(),
            5
        );
        let html = "<!DOCTYPE html><html><title>Attention Required</title></html>";
        let err = token_response(403, html, &g, "x").unwrap_err();
        assert_eq!(err.exit_code(), 5);
        assert!(err.to_string().contains("HTML"), "{err}");
        // A short page behind leading whitespace is still a page: the head
        // is taken from the trimmed body, so the recapture hint survives.
        let padded = "\n  <html><body>blocked</body></html>";
        let err = token_response(403, padded, &g, "x").unwrap_err();
        assert!(err.to_string().contains("HTML page"), "{err}");
        assert!(err.to_string().contains(&format!("`{RELOGIN}`")), "{err}");
        let plain = token_response(502, "bad gateway", &g, "x").unwrap_err();
        assert!(plain.to_string().contains("unparseable"), "{plain}");
        let boom = json!({ "error": "server_error" }).to_string();
        assert_eq!(
            token_response(500, &boom, &g, "x").unwrap_err().exit_code(),
            5
        );
    }

    #[test]
    fn a_success_without_a_token_is_upstream() {
        let err = token_response(200, "{}", &Auth0Grant::default(), "x").unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }
}
