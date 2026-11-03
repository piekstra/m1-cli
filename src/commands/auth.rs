//! `m1f auth` — login, status, logout, and headless credential rotation.
//!
//! # Two logins
//!
//! **The browser session** is the one that works today. Since 2026-10-27
//! Cloudflare answers the legacy password mutation with an HTTP 403 HTML
//! page, and M1's own web app signs in through Auth0 instead (`crate::auth0`
//! has the shape). The owner signs in at dashboard.m1.com and the session
//! auth0-spa-js keeps in localStorage is handed over by one of two routes:
//! `auth login --browser` reads it out of a Chrome window the owner signs in
//! through (`pk_cli_browser`), and `auth login --browser-session --stdin` takes
//! it copied out of DevTools, the fallback without Chrome. Both go through the
//! one reader (`auth0::parse_browser_capture` / `auth0::parse_captured`, which
//! differ only in how a refusal is reported), the one check
//! (`viewer.isAuthenticated`) and the one keychain item, so they store the same thing; the session is
//! renewed with its refresh token from then on. No password or code passes
//! through the CLI.
//!
//! **The password login** (the rest of this module's history, below) is kept
//! for the day the edge lets it through again, and names the 403 trap when it
//! does not ([`crate::client::legacy_login_blocked`]).
//!
//! # How MFA actually works here (password login)
//!
//! There is **no challenge object and no separate resume mutation.** `outcome`
//! on the `Authenticate` payload is a plain object, not a union. When M1 wants
//! a verification code it says so through `error` (a scalar), and the client is
//! expected to **replay the same `Authenticate` mutation** with `emailCode`
//! added alongside the original username and password.
//!
//! That shapes the CLI: `m1f auth login --code <CODE>` is not "resume a parked
//! session", it is "run the same login again, with the code". It therefore
//! needs the password a second time — which is deliberate. `m1f` never stores
//! a password, and storing one just to make the second step convenient would
//! trade a real security property for a keystroke.
//!
//! Because there is no server-side session to keep alive, nothing about the
//! first attempt is load-bearing. We record only a breadcrumb so `auth status`
//! can say a code is expected. Codes are rate-limited: one attempt, then read
//! the error rather than retrying.

use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserArgs, BrowserError, Launch, DEFAULT_TIMEOUT};
use pk_cli_config::ConfigStore;
use pk_cli_core::{output, CliError};
use pk_cli_secrets::Secret;
use serde_json::{json, Value};

use super::{emit, Ctx};
use crate::client::{M1Client, PendingChallenge, TokenBundle};
use crate::config::Config;
use crate::{auth0, graphql};

/// `--browser` is the browser session, captured rather than piped in, so it
/// takes no other source and none of the password login's flags; clap refuses
/// those combinations (exit 2) before anything else runs. With
/// `--browser-session` it means the same as alone.
#[derive(clap::Args, Debug)]
#[command(mut_arg("browser", |a| a.conflicts_with_all(["stdin", "from_env", "username", "code"])))]
pub struct LoginCmdArgs {
    #[command(flatten)]
    pub base: LoginArgs,

    #[command(flatten)]
    pub browser: BrowserArgs,

    /// Store a session captured from M1's web app instead of sending a
    /// password: read from --stdin or --from-env (the DevTools steps above),
    /// or captured with --browser, which implies this flag.
    #[arg(long, conflicts_with_all = ["username", "code"])]
    pub browser_session: bool,

    /// Email address to log in as. Defaults to the configured username.
    #[arg(long, value_name = "EMAIL")]
    pub username: Option<String>,

    /// Emailed verification code. Replays the whole login with the code
    /// attached, so you will be asked for your password again.
    #[arg(long, value_name = "CODE")]
    pub code: Option<String>,
}

impl LoginCmdArgs {
    /// Whether this is the browser-session login, by either route.
    pub fn is_browser_session(&self) -> bool {
        self.browser_session || self.browser.browser
    }

    /// The command that retries this browser-session login.
    fn retry_hint(&self) -> &'static str {
        if self.base.overwrite {
            auth0::RELOGIN
        } else {
            auth0::LOGIN
        }
    }
}

pub fn login(ctx: &Ctx, store: &ConfigStore, args: &LoginCmdArgs) -> Result<(), CliError> {
    if args.is_browser_session() {
        return browser_session_login(ctx, args);
    }
    // `--code` is not a separate flow: it is the same login, replayed with the
    // code attached. So the guard below applies to both.
    if ctx.tokens()?.is_some() && !args.base.overwrite && args.code.is_none() {
        return Err(CliError::Usage(
            "already logged in; pass --overwrite to replace the stored session".into(),
        ));
    }

    ctx.before_signin()?;
    let username = resolve_username(ctx, args)?;
    let prompt = if args.base.non_interactive {
        None
    } else if args.code.is_some() {
        Some("M1 password (again, to replay the login with your code)")
    } else {
        Some("M1 password")
    };
    let password = args.base.source.read(prompt)?;

    // Persist the identity up front so a follow-up `--code` run and
    // `auth status` both know who we are.
    let mut cfg: Config = store.load()?;
    cfg.username = Some(username.clone());
    store.save(&cfg)?;

    let mut input = json!({ "username": username, "password": password.expose() });
    if let Some(code) = &args.code {
        input["emailCode"] = json!(code);
    }

    let client = ctx.anonymous()?;
    let data = client.execute_with(
        graphql::AUTHENTICATE,
        json!({ "input": input }),
        Some("Authenticate"),
        crate::client::legacy_login_blocked,
    )?;

    // Dual-channel failure: `client::execute` already rejected a populated
    // top-level `errors` array. This catches the other channel — HTTP 200, a
    // clean envelope, and `didSucceed: false`.
    //
    // But first: an MFA demand *also* arrives as `didSucceed: false`, and it is
    // not an error the user should be told to debug. Separate the two before
    // failing.
    if let Some(reason) = failure_reason(&data) {
        if needs_email_code(&reason) && args.code.is_none() {
            ctx.store_pending(&PendingChallenge {
                challenge_id: String::new(),
                method: Some("emailCode".into()),
                started_at: None,
            })?;
            if !ctx.common.quiet {
                eprintln!(
                    "M1 sent a verification code. Finish with:\n  \
                     m1f auth login --code <CODE>\n\
                     (it will ask for your password again — the whole login is replayed)"
                );
            }
            emit(
                ctx,
                "auth-challenge",
                json!({
                    "pending": true,
                    "method": "emailCode",
                    "next": "m1f auth login --code <CODE>",
                    "detail": reason
                }),
                output::render,
            );
            return Ok(());
        }
        return Err(CliError::Auth(reason));
    }

    let bundle = extract_tokens(&data).ok_or_else(|| {
        CliError::Upstream(
            "M1 reported success but returned no access token — the auth shape has \
             probably changed (see docs/api.md)"
                .into(),
        )
    })?;
    ctx.store_login(&bundle)?;
    ctx.clear_pending()?;
    let status = status_dto(ctx, Some(&bundle), Some(&username));
    status.emit(ctx.common.json);
    Ok(())
}

/// `auth login --browser` / `--browser-session`: store a session taken from
/// M1's web app, after one read proves M1 accepts it.
///
/// With `--browser` the session is read out of a Chrome window the owner
/// signs in through. Otherwise it is several kilobytes of JSON, longer than a
/// terminal line takes (macOS cuts a canonical-mode line at 1024 bytes), so it
/// is read only from `--stdin` or `--from-env`, never a prompt. Either way it
/// goes through the same reader, check and store. An access token that has
/// already lapsed is renewed with its refresh token before the check, so a
/// capture copied a while ago still lands.
fn browser_session_login(ctx: &Ctx, args: &LoginCmdArgs) -> Result<(), CliError> {
    let mut bundle = if args.browser.browser {
        // The keychain check comes before the window: a sign-in the owner
        // has finished is not thrown away for want of --overwrite.
        refuse_overwrite(ctx, args)?;
        ctx.before_signin()?;
        let captured = capture_from_browser(ctx, args.retry_hint())?;
        auth0::parse_browser_capture(captured.expose())?
    } else {
        if !args.base.source.stdin && args.base.source.from_env.is_none() {
            return Err(CliError::Usage(format!(
                "the browser session is captured with `{}`, or read from --stdin or --from-env \
                 <VAR>, not typed: copy it with the DevTools snippet in `m1f auth login --help`, \
                 then run `pbpaste | {}`",
                auth0::LOGIN,
                auth0::STDIN_LOGIN
            )));
        }
        // Before the read: a session piped in once cannot be read again.
        ctx.before_signin()?;
        // The pasted session is input: read and check it before the keychain.
        let raw = args.base.source.read(None)?;
        let bundle = auth0::parse_captured(raw.expose())?;
        refuse_overwrite(ctx, args)?;
        bundle
    };
    if !args.base.no_verify {
        if expiry_passed(&bundle) {
            let (Some(grant), Some(refresh)) = (bundle.auth0.clone(), bundle.refresh_token.clone())
            else {
                return Err(CliError::Auth(format!(
                    "the session's access token has expired and it carries no refresh token — \
                     sign in again: `{}`",
                    args.retry_hint()
                )));
            };
            bundle = auth0::refresh(&grant, &refresh, ctx.common.verbose)?;
        }
        verify(ctx, &bundle)?;
    }
    ctx.store_login(&bundle)?;
    ctx.clear_pending()?;
    if !ctx.common.quiet {
        let renewal = if bundle.refresh_token.is_some() {
            "it renews itself with its refresh token"
        } else {
            "no refresh token came with it, so it lasts until the access token expires"
        };
        let how = if args.base.no_verify {
            "stored (unverified)"
        } else {
            "verified and stored"
        };
        // The browser route closed its tab and Chrome itself; a copied
        // session may still be held by the window it was copied from.
        let close = if args.browser.browser {
            ""
        } else {
            " If you copied it from a browser you keep using, close that window now (see `m1f \
             auth login --help`)."
        };
        eprintln!("M1 browser session {how} in the OS keychain; {renewal}.{close}");
    }
    let status = status_dto(ctx, Some(&bundle), ctx.cfg.username.as_deref());
    status.emit(ctx.common.json);
    Ok(())
}

fn refuse_overwrite(ctx: &Ctx, args: &LoginCmdArgs) -> Result<(), CliError> {
    if ctx.tokens()?.is_some() && !args.base.overwrite {
        return Err(CliError::Usage(
            "already logged in; pass --overwrite to replace the stored session".into(),
        ));
    }
    Ok(())
}

/// Open a Chrome window at the dashboard, wait while the owner signs in, and
/// read the session out of it ([`auth0::browser_capture`]). The tab closes the
/// moment the session is read, then Chrome quits and its profile is deleted.
fn capture_from_browser(ctx: &Ctx, retry_hint: &str) -> Result<Secret, CliError> {
    let launch = Launch::new(crate::BIN)
        .url(crate::client::WEB_ORIGIN)
        .quiet(ctx.common.quiet)
        .login_hint(retry_hint);
    match pk_cli_browser::capture(launch, &auth0::browser_capture()?, DEFAULT_TIMEOUT) {
        Ok(captured) => captured
            .into_value()
            .ok_or_else(|| CliError::Other("the browser capture read no session".into())),
        Err(BrowserError::ChromeNotFound(why)) => Err(chrome_not_found(&why)),
        Err(e) => Err(e.into()),
    }
}

/// No Chrome: the fallback is the DevTools copy, in any browser.
fn chrome_not_found(why: &str) -> CliError {
    CliError::Other(format!(
        "{why}. Without Chrome, sign in at https://{} in any browser and pipe the session in: \
         the DevTools steps in `m1f auth login --help`, then `pbpaste | {}`",
        auth0::DASHBOARD_HOST,
        auth0::STDIN_LOGIN
    ))
}

/// One authenticated read: `viewer.isAuthenticated` must be `true`. M1
/// answers `false` — not an error — for a token it does not accept.
fn verify(ctx: &Ctx, bundle: &TokenBundle) -> Result<(), CliError> {
    let client = M1Client::new(
        &ctx.cfg.base_url(),
        Some(bundle.access_token.clone()),
        ctx.common.verbose,
    )?;
    let data = client.execute(
        graphql::VIEWER_IS_AUTHENTICATED,
        json!({}),
        Some("ViewerIsAuthenticated"),
    )?;
    verdict(&data)
}

/// The verification read's answer. Pure, so the three branches are tested.
fn verdict(data: &Value) -> Result<(), CliError> {
    match data.pointer("/viewer/isAuthenticated") {
        Some(Value::Bool(true)) => Ok(()),
        Some(Value::Bool(false)) => Err(CliError::Auth(format!(
            "M1 did not accept the session (viewer.isAuthenticated is false) — it may be from \
             a signed-out tab or another environment; sign in again: `{}`. Nothing was stored.",
            auth0::LOGIN
        ))),
        _ => Err(CliError::Upstream(
            "M1's answer to the session check had no `viewer.isAuthenticated` — the shape may \
             have changed (see docs/api.md). Nothing was stored."
                .into(),
        )),
    }
}

/// The payload's own failure reason, if it reports one.
///
/// `error` is a **scalar** on this API, not an object, so this is usually a
/// bare string.
fn failure_reason(data: &Value) -> Option<String> {
    crate::client::check_did_succeed(data).err().map(|e| {
        // `check_did_succeed` returns a CliError; we want the raw text so the
        // caller can classify it.
        e.to_string()
    })
}

/// Whether a failure reason is really "we need the emailed code".
///
/// The `error` field is an `AuthenticateErrorEnum` (schema-verified), and the
/// members that mean "send me a code" are `CODE_REQUIRED` and
/// `EMAIL_AMFA_REQUIRED`. Those are matched first and exactly. The looser
/// needles are kept as a fallback for shapes the schema doesn't promise (a
/// gateway rewording the enum into prose), and the whole check still fails
/// *safe*: an unrecognized reason — including `INCORRECT_CREDENTIALS` and
/// `USER_ACCOUNT_LOCKED` — is reported as an error, never swallowed as a
/// silent MFA prompt.
fn needs_email_code(reason: &str) -> bool {
    let r = reason.to_ascii_lowercase();
    [
        "code_required",
        "amfa_required",
        "emailcode",
        "email code",
        "verification code",
        "mfa",
        "2fa",
        "two-factor",
        "confirmation code",
        "otp",
    ]
    .iter()
    .any(|needle| r.contains(needle))
}

pub fn status(ctx: &Ctx) -> Result<(), CliError> {
    let bundle = ctx.tokens()?;
    if bundle.is_none() && ctx.pending()?.is_some() && !ctx.common.quiet {
        eprintln!(
            "a login is awaiting a verification code — finish with `m1f auth login --code <CODE>`"
        );
    }
    let status = status_dto(ctx, bundle.as_ref(), ctx.cfg.username.as_deref());
    status.emit(ctx.common.json);
    Ok(())
}

pub fn logout(ctx: &Ctx, store: &ConfigStore, args: &LogoutArgs) -> Result<(), CliError> {
    ctx.forget_tokens()?;
    ctx.clear_pending()?;
    if args.forget {
        store.clear()?;
    }
    if !ctx.common.quiet {
        eprintln!("logged out (stored tokens cleared)");
        eprintln!(
            "note: this clears the local copy only — to end the session at M1, change \
             your password or sign out other devices in M1's own app"
        );
    }
    Ok(())
}

/// Raw keychain write for rotation / headless setup.
///
/// Accepts a full token bundle as JSON (the keychain's own shape, so a
/// bundle moves between machines intact), a captured browser session (any
/// shape `auth login --browser-session` reads), or a bare legacy refresh
/// token. Unlike `auth login`, nothing is verified.
pub fn set_credential(ctx: &Ctx, args: &SetCredentialArgs) -> Result<(), CliError> {
    if ctx.tokens()?.is_some() && !args.overwrite {
        return Err(CliError::Usage(
            "a session is already stored; pass --overwrite to replace it".into(),
        ));
    }
    ctx.before_signin()?;
    let secret = args.source.read(None)?;
    let bundle = parse_credential(secret.expose())?;
    ctx.store_login(&bundle)?;
    if !ctx.common.quiet {
        eprintln!("session stored in the OS keychain");
    }
    Ok(())
}

/// Interpret a pasted credential: the keychain's own bundle, a captured
/// browser session, or a bare legacy refresh token.
fn parse_credential(raw: &str) -> Result<TokenBundle, CliError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(CliError::Usage("empty credential".into()));
    }
    if raw.starts_with('{') {
        let v: Value = serde_json::from_str(raw).map_err(|e| {
            CliError::Usage(format!(
                "credential looks like JSON but does not parse: {e}"
            ))
        })?;
        // An Auth0 cache entry (`body`), token response (`token_type`,
        // `expires_in`) or localStorage map goes to the browser-session
        // reader; anything else is the keychain's own bundle shape.
        let captured = v.get("body").is_some()
            || v.get("token_type").is_some()
            || v.get("expires_in").is_some()
            || v.as_object()
                .is_some_and(|m| m.keys().any(|k| k.starts_with(auth0::CACHE_KEY_PREFIX)));
        if captured {
            return auth0::parse_captured(raw);
        }
        let bundle: TokenBundle = serde_json::from_value(v).map_err(|e| {
            CliError::Usage(format!(
                "credential looks like JSON but isn't a token bundle: {e}"
            ))
        })?;
        if bundle.access_token.is_empty() && bundle.refresh_token.is_none() {
            return Err(CliError::Usage(
                "token bundle has neither an access_token nor a refresh_token".into(),
            ));
        }
        return Ok(bundle);
    }
    // A bare token: treat it as a legacy refresh token, since that is the one
    // worth moving between machines. The first read exchanges it for an
    // access token. (A bare Auth0 access token goes through `auth login
    // --browser-session`, which verifies it.)
    Ok(TokenBundle {
        access_token: String::new(),
        refresh_token: Some(raw.to_string()),
        expires_at: None,
        auth0: None,
    })
}

/// Exchange a refresh token for a fresh bundle. Called by `Ctx::refresh`.
pub fn refresh_tokens(ctx: &Ctx, refresh_token: &str) -> Result<TokenBundle, CliError> {
    let client = ctx.anonymous()?;
    let data = client.execute(
        graphql::REAUTHENTICATE,
        json!({ "input": { "refreshToken": refresh_token } }),
        Some("Reauthenticate"),
    )?;
    crate::client::check_did_succeed(&data)?;

    let mut bundle = extract_tokens(&data).ok_or_else(|| {
        CliError::Auth("refreshing the session returned no token — run `m1f auth login`".into())
    })?;
    // Refresh tokens **rotate** on this API: the response carries a new one and
    // M1 retires the old. Keeping the old value would work exactly once and
    // then fail as if the session had been revoked.
    if bundle.refresh_token.is_none() {
        bundle.refresh_token = Some(refresh_token.to_string());
    }
    Ok(bundle)
}

fn status_dto(ctx: &Ctx, bundle: Option<&TokenBundle>, username: Option<&str>) -> AuthStatus {
    let mut status = AuthStatus::new(true, false, method_of(bundle));
    status.username = username.map(str::to_string);
    status.account = ctx
        .account_override
        .map(str::to_string)
        .or_else(|| ctx.cfg.account.clone());
    status.credential_in_keychain = Some(bundle.is_some());
    if let Some(b) = bundle {
        let expires_at = b
            .expires_at
            .clone()
            .or_else(|| pk_cli_auth::token::expires_at(&b.access_token));
        let expired = expiry_passed(b);
        // A lapsed access token with a refresh token is still usable: the
        // next read renews it (unless auto_login is off).
        let renewable = b.refresh_token.is_some() && ctx.cfg.auto_login();
        status.authenticated = !expired || renewable;
        status.session_valid = Some(!expired);
        status.expires_at = expires_at;
    }
    status
}

/// How the stored session was obtained: a password bundle is the legacy
/// login's; anything else — an Auth0 bundle, or nothing stored, where the
/// browser session is the login that works — reports `browser-session`.
fn method_of(bundle: Option<&TokenBundle>) -> AuthMethod {
    match bundle {
        Some(b) if b.auth0.is_none() => AuthMethod::Password,
        _ => AuthMethod::BrowserSession,
    }
}

/// Whether the stored access token has passed its expiry.
///
/// Advisory only: the server is the authority, so a token that looks live can
/// still come back `UNAUTHENTICATED`, which the read path handles by refreshing.
fn expiry_passed(bundle: &TokenBundle) -> bool {
    if bundle.access_token.is_empty() {
        return true;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    pk_cli_auth::token::is_expired(
        &bundle.access_token,
        now,
        pk_cli_auth::token::DEFAULT_SKEW_SECS,
    )
}

fn resolve_username(ctx: &Ctx, args: &LoginCmdArgs) -> Result<String, CliError> {
    if let Some(u) = &args.username {
        return Ok(u.clone());
    }
    if let Some(u) = &ctx.cfg.username {
        return Ok(u.clone());
    }
    if !ctx.common.interactive() {
        return Err(CliError::Usage(
            "no username — pass --username <EMAIL> or run `m1f config set username <EMAIL>`".into(),
        ));
    }
    eprint!("M1 email: ");
    use std::io::Write;
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::Usage(format!("reading username: {e}")))?;
    let line = line.trim().to_string();
    if line.is_empty() {
        return Err(CliError::Usage("no username given".into()));
    }
    Ok(line)
}

// ---------------------------------------------------------------------------
// Tolerant extraction
// ---------------------------------------------------------------------------
//
// The wrapper key around the auth payload is not publicly documented (it may
// be `authenticate`, `login`, `session`, …), so rather than hard-code one path
// we search the response for the token fields. Presence of an access token is
// unambiguous; this cannot false-positive on a read response, because reads
// never carry one.

fn find_first<'a>(v: &'a Value, keys: &[&str], depth: usize) -> Option<&'a Value> {
    if depth == 0 {
        return None;
    }
    if let Value::Object(map) = v {
        for k in keys {
            if let Some(found) = map.get(*k) {
                if !found.is_null() {
                    return Some(found);
                }
            }
        }
        for (_, child) in map {
            if let Some(found) = find_first(child, keys, depth - 1) {
                return Some(found);
            }
        }
    }
    None
}

pub fn extract_tokens(data: &Value) -> Option<TokenBundle> {
    let access = find_first(data, &["accessToken", "access_token", "token"], 6)?
        .as_str()?
        .to_string();
    if access.is_empty() {
        return None;
    }
    let refresh = find_first(data, &["refreshToken", "refresh_token"], 6)
        .and_then(Value::as_str)
        .map(str::to_string);
    // M1's payload carries `expiresIn` (seconds from now, an Int — schema-
    // verified) rather than an absolute timestamp; both spellings of an
    // absolute one are still accepted first in case a gateway inlines one.
    let expires_at = find_first(data, &["expiresAt", "expires_at"], 6)
        .and_then(crate::parse::iso_or_rfc3339)
        .or_else(|| {
            find_first(data, &["expiresIn", "expires_in"], 6)
                .and_then(Value::as_i64)
                .map(|secs| {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    pk_cli_core::dates::fmt_rfc3339(now + secs)
                })
        });
    Some(TokenBundle {
        access_token: access,
        refresh_token: refresh,
        expires_at,
        auth0: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tokens_are_found_under_an_unknown_wrapper_key() {
        let data = json!({
            "authenticate": {
                "accessToken": "acc", "refreshToken": "ref",
                "expiresAt": "2026-08-11T12:00:00Z"
            }
        });
        let b = extract_tokens(&data).expect("found");
        assert_eq!(b.access_token, "acc");
        assert_eq!(b.refresh_token.as_deref(), Some("ref"));
        assert_eq!(b.expires_at.as_deref(), Some("2026-08-11T12:00:00Z"));
    }

    #[test]
    fn snake_case_spellings_also_work() {
        let data = json!({ "login": { "access_token": "a", "refresh_token": "r" } });
        let b = extract_tokens(&data).expect("found");
        assert_eq!(b.access_token, "a");
        assert_eq!(b.refresh_token.as_deref(), Some("r"));
    }

    #[test]
    fn a_response_with_no_token_yields_none() {
        assert!(extract_tokens(&json!({ "viewer": { "id": "1" } })).is_none());
        assert!(extract_tokens(&json!({ "authenticate": { "accessToken": "" } })).is_none());
    }

    #[test]
    fn credential_parses_as_bundle_or_bare_refresh_token() {
        let bundle = parse_credential(r#"{"access_token":"a","refresh_token":"r"}"#).unwrap();
        assert_eq!(bundle.access_token, "a");

        let bare = parse_credential("  refresh-me  ").unwrap();
        assert_eq!(bare.refresh_token.as_deref(), Some("refresh-me"));
        assert!(bare.access_token.is_empty());
    }

    #[test]
    fn an_empty_or_useless_credential_is_rejected() {
        assert!(parse_credential("").is_err());
        assert!(parse_credential("{}").is_err());
        assert!(parse_credential("{not json").is_err());
    }

    #[test]
    fn an_empty_access_token_counts_as_expired() {
        let b = TokenBundle {
            access_token: String::new(),
            refresh_token: Some("r".into()),
            expires_at: None,
            auth0: None,
        };
        assert!(expiry_passed(&b));
    }

    #[test]
    fn set_credential_reads_a_captured_browser_session_too() {
        let entry = json!({
            "body": {
                "access_token": "DUMMY.ACCESS.TOKEN",
                "refresh_token": "DUMMY.REFRESH.TOKEN",
                "audience": crate::auth0::AUDIENCE
            },
            "expiresAt": 1_900_000_000
        });
        let b = parse_credential(&entry.to_string()).unwrap();
        assert_eq!(b.access_token, "DUMMY.ACCESS.TOKEN");
        assert!(b.auth0.is_some(), "an Auth0 capture renews at Auth0");
        // The keychain's own Auth0 bundle round-trips as itself.
        let own = serde_json::to_string(&b).unwrap();
        let again = parse_credential(&own).unwrap();
        assert_eq!(again.auth0, b.auth0);
        assert_eq!(again.refresh_token, b.refresh_token);
    }

    #[test]
    fn the_verification_read_needs_a_true_flag() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/reads/viewer-is-authenticated.json"
        ))
        .unwrap();
        assert!(verdict(&fixture["data"]).is_ok());
        let refused = verdict(&json!({ "viewer": { "isAuthenticated": false } })).unwrap_err();
        assert_eq!(refused.exit_code(), 3);
        assert!(
            refused.to_string().contains("Nothing was stored"),
            "{refused}"
        );
        let odd = verdict(&json!({ "viewer": {} })).unwrap_err();
        assert_eq!(odd.exit_code(), 5);
    }

    /// The browser route stores what the piped route stores for the same
    /// value: one reader, and the fixture is the string the capture returns.
    #[test]
    fn a_captured_session_reads_as_the_piped_one_does() {
        let raw = include_str!("../../tests/fixtures/auth/auth0-spa-cache.json");
        let captured = crate::auth0::parse_browser_capture(raw).unwrap();
        assert_eq!(captured, crate::auth0::parse_captured(raw).unwrap());
        assert_eq!(method_of(Some(&captured)), AuthMethod::BrowserSession);
        assert_eq!(captured.login_hint(), crate::auth0::RELOGIN);
    }

    #[test]
    fn no_chrome_points_at_the_devtools_route() {
        let err = chrome_not_found("no Chrome found");
        assert_eq!(err.exit_code(), 1);
        assert!(
            err.to_string()
                .contains("pbpaste | m1f auth login --browser-session --stdin"),
            "{err}"
        );
    }

    #[test]
    fn the_retry_hint_keeps_overwrite() {
        let parse = |flags: &[&str]| {
            use clap::Parser;
            #[derive(Parser)]
            struct Cli {
                #[command(flatten)]
                login: LoginCmdArgs,
            }
            Cli::try_parse_from(["m1f"].iter().chain(flags))
                .unwrap()
                .login
        };
        assert_eq!(parse(&["--browser"]).retry_hint(), crate::auth0::LOGIN);
        assert_eq!(
            parse(&["--browser", "--overwrite"]).retry_hint(),
            crate::auth0::RELOGIN
        );
    }

    #[test]
    fn the_status_method_follows_the_stored_bundle() {
        let legacy = TokenBundle {
            access_token: "a".into(),
            ..TokenBundle::default()
        };
        assert_eq!(method_of(Some(&legacy)), AuthMethod::Password);
        let browser = TokenBundle {
            auth0: Some(crate::auth0::Auth0Grant::default()),
            ..legacy
        };
        assert_eq!(method_of(Some(&browser)), AuthMethod::BrowserSession);
        assert_eq!(method_of(None), AuthMethod::BrowserSession);
    }
}
