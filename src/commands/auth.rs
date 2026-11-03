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
//! The window runs in a Chrome profile `m1f` keeps between sign-ins, so M1's
//! own sign-in remembers this device and a later `--browser` often needs no
//! input. It is a full Chrome profile: M1's cookies, browsing history with full
//! URLs, query strings included, and the HTTP cache. Chrome's cookie encryption
//! does not cover the last two, so the directory's `0700` mode is their only
//! protection, and ordinary backups usually include it. On
//! Linux with no desktop keyring Chrome encrypts the cookies with a fixed, publicly
//! known key, so there the session cookie has only `0700` too. The profile stays
//! on disk until `auth logout` removes it ([`run_logout`]), after a failed
//! sign-in too ([`through_the_window`]).
//!
//! The session's tokens do not stay. The page keeps them in `localStorage`, so
//! [`browser_launch`] turns on `clear_site_storage`. The capture only reads
//! ([`crate::auth0::CAPTURE_EXPRESSION`]), and the tab closes only on a session M1
//! accepts ([`confirm_candidate`]). docs/api.md, "The kept profile", has the detail.
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

use std::sync::Mutex;

use pk_cli_auth::{AuthMethod, AuthStatus, LoginArgs, LogoutArgs, SetCredentialArgs};
use pk_cli_browser::{BrowserArgs, BrowserError, Captured, Confirm, Launch, DEFAULT_TIMEOUT};
use pk_cli_config::ConfigStore;
use pk_cli_core::{output, CliError};
use pk_cli_secrets::{CredentialStore, Secret};
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
    fn retry_hint(&self) -> String {
        let login = if self.base.overwrite {
            auth0::RELOGIN
        } else {
            auth0::LOGIN
        };
        if self.browser.fresh_profile {
            format!("{login} --fresh-profile")
        } else {
            login.to_string()
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

    let username = resolve_username(ctx, args)?;
    ctx.before_signin()?;
    let prompt = if args.base.non_interactive {
        None
    } else if args.code.is_some() {
        Some("M1 password (again, to replay the login with your code)")
    } else {
        Some("M1 password")
    };
    let password = args.base.source.read(prompt)?;

    remember_username(ctx.creds, store, &username)?;

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
    if args.browser.browser {
        return browser_sign_in(ctx, args);
    }
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
    ctx.lock_usable()?;
    // The pasted session is input: read and check it before the keychain.
    let raw = args.base.source.read(None)?;
    let mut bundle = auth0::parse_captured(raw.expose())?;
    refuse_overwrite(ctx, args)?;
    // Only a copied session is renewed here. One from the window was confirmed
    // unexpired a moment ago.
    if !args.base.no_verify && expiry_passed(&bundle) {
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
    store_session(ctx, args, &bundle)
}

/// The one check and the one keychain item both routes share.
fn store_session(ctx: &Ctx, args: &LoginCmdArgs, bundle: &TokenBundle) -> Result<(), CliError> {
    if !args.base.no_verify {
        verify(ctx, bundle)?;
    }
    ctx.store_login(bundle)?;
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
        // The browser route closed its tab and Chrome itself, and may leave a
        // profile; a copied session may still be held by the window it was
        // copied from.
        let close = if args.browser.browser {
            if keeps_profile(scratch_profile(ctx.creds, args)) {
                " The browser profile, with M1's cookies in it, stays on disk for the next \
                 sign-in; `m1f auth logout` removes it."
            } else {
                ""
            }
        } else {
            " If you copied it from a browser you keep using, close that window now (see `m1f \
             auth login --help`)."
        };
        eprintln!("M1 browser session {how} in the OS keychain; {renewal}.{close}");
    }
    let status = status_dto(ctx, Some(bundle), ctx.cfg.username.as_deref());
    status.emit(ctx.common.json);
    Ok(())
}

/// Persist the identity up front so a follow-up `--code` run and `auth status`
/// both know who we are. Not on a keychain pointed elsewhere: this is not the real
/// session, so it must not change the real config.
fn remember_username(
    creds: &CredentialStore,
    store: &ConfigStore,
    username: &str,
) -> Result<(), CliError> {
    if keychain_redirected(creds) {
        return Ok(());
    }
    let mut cfg: Config = store.load()?;
    cfg.username = Some(username.to_string());
    store.save(&cfg)
}

fn refuse_overwrite(ctx: &Ctx, args: &LoginCmdArgs) -> Result<(), CliError> {
    if ctx.tokens()?.is_some() && !args.base.overwrite {
        return Err(CliError::Usage(
            "already logged in; pass --overwrite to replace the stored session".into(),
        ));
    }
    Ok(())
}

/// `--browser`: open a Chrome window at the dashboard, wait until it holds a
/// session M1 accepts, and read it out ([`auth0::browser_capture`]). The tab
/// closes the moment the session is read, then Chrome quits. Its profile stays
/// for the next sign-in, unless a scratch one was asked for
/// ([`scratch_profile`]).
fn browser_sign_in(ctx: &Ctx, args: &LoginCmdArgs) -> Result<(), CliError> {
    let scratch = scratch_profile(ctx.creds, args);
    // The keychain check comes before the window: a sign-in the owner has
    // finished is not thrown away for want of --overwrite.
    refuse_overwrite(ctx, args)?;
    ctx.before_signin()?;
    let launch = browser_launch(scratch, ctx.common.quiet, args.retry_hint());
    let endpoint = ctx.cfg.base_url();
    let verbose = ctx.common.verbose;
    let no_verify = args.base.no_verify;
    let refused = Mutex::new(None);
    let capture = auth0::browser_capture()?.confirm(move |candidate| {
        confirm_candidate(candidate, &refused, |bundle| {
            if no_verify {
                Ok(())
            } else {
                read_viewer(&endpoint, verbose, bundle)
            }
        })
    });
    through_the_window(
        scratch,
        || pk_cli_browser::capture(launch, &capture, DEFAULT_TIMEOUT),
        |bundle| store_session(ctx, args, &bundle),
    )
}

/// The window's Chrome. The page keeps the session's tokens in `localStorage`, and
/// a refresh token left on disk could be presented by a later window after `m1f`
/// has retired it, which Auth0 answers by revoking the whole family. So the kept
/// profile keeps its cookies and never its site storage.
fn browser_launch(scratch: bool, quiet: bool, hint: String) -> Launch {
    Launch::new(crate::BIN)
        .url(crate::client::WEB_ORIGIN)
        .clear_site_storage(true)
        .fresh_profile(scratch)
        .quiet(quiet)
        .login_hint(hint)
}

/// A browser sign-in from the window on, with every way it can fail in one
/// place, so a new one cannot miss [`failed_sign_in`]: the window's own ending,
/// the confirm hook's, the read after it and the keychain write.
///
/// Only four failures skip the note, because they end the sign-in before this
/// Chrome uses the profile: no Chrome, a malformed launch, and a profile refused
/// for repair or already in use, whose own messages name the path and the fix.
fn through_the_window(
    scratch: bool,
    capture: impl FnOnce() -> Result<Captured, BrowserError>,
    finish: impl FnOnce(TokenBundle) -> Result<(), CliError>,
) -> Result<(), CliError> {
    let captured = match capture() {
        Err(BrowserError::ChromeNotFound(why)) => return Err(chrome_not_found(&why)),
        Err(
            e @ (BrowserError::Invalid(_)
            | BrowserError::Profile(_)
            | BrowserError::ProfileInUse(_)),
        ) => return Err(e.into()),
        other => other,
    };
    captured
        .map_err(CliError::from)
        .and_then(|captured| {
            let session = captured
                .value()
                .ok_or_else(|| CliError::Other("the browser capture read no session".into()))?;
            finish(auth0::parse_browser_capture(session.expose())?)
        })
        .map_err(|e| failed_sign_in(e, scratch))
}

/// Whether this sign-in runs in a scratch profile: `--fresh-profile`, or a
/// keychain pointed away from the real session, which must not sign in from the
/// real session's cookies.
fn scratch_profile(creds: &CredentialStore, args: &LoginCmdArgs) -> bool {
    args.browser.fresh_profile || keychain_redirected(creds)
}

/// Whether `M1F_KEYCHAIN_SERVICE` has this run on another keychain service. The
/// kept profile has no such variable: there is only the real one.
fn keychain_redirected(creds: &CredentialStore) -> bool {
    creds.service() != CredentialStore::for_binary(crate::BIN).service()
}

/// Whether a sign-in runs in the kept profile: not in a scratch one, and only
/// where the crate keeps one (`Launch::spawn`'s macOS and Linux).
fn keeps_profile(scratch: bool) -> bool {
    !scratch && cfg!(unix)
}

/// What a failed sign-in leaves behind, for its error. The kept profile stays
/// with whatever the sign-in got as far as, which can be a live session, and the
/// owner may move on and never log out.
const PROFILE_STAYS: &str = "The browser profile stays on disk with what that window left in it, \
                             which can be a live session; once no window is using it, `m1f auth \
                             logout` removes it and clears any stored session with it, and \
                             `--fresh-profile` signs in without it.";

/// A failed sign-in, saying that the kept profile stays. A scratch one is
/// already gone. The exit code does not change.
fn failed_sign_in(error: CliError, scratch: bool) -> CliError {
    if !keeps_profile(scratch) {
        return error;
    }
    reworded(error, |m| {
        format!("{}. {PROFILE_STAYS}", m.trim_end_matches('.'))
    })
}

/// The same failure, with the same exit code, saying something else.
fn reworded(error: CliError, say: impl FnOnce(String) -> String) -> CliError {
    match error {
        CliError::Usage(m) => CliError::Usage(say(m)),
        CliError::Auth(m) => CliError::Auth(say(m)),
        CliError::NotFound(m) => CliError::NotFound(say(m)),
        CliError::Upstream(m) => CliError::Upstream(say(m)),
        CliError::ConfirmationRequired(m) => CliError::ConfirmationRequired(say(m)),
        CliError::Keychain(m) => CliError::Keychain(say(m)),
        CliError::Other(m) => CliError::Other(say(m)),
    }
}

/// Whether the session in the window is one to take, which closes the tab.
///
/// Site storage goes before Chrome starts ([`browser_launch`]), so what the page
/// holds was written in this window. Taking a session that is expired or that M1
/// refuses would still close the tab before M1's page could ask the owner to sign
/// in, so either keeps the tab open.
///
/// A session is never renewed here: the page that holds it can renew it too, and
/// Auth0 answers the second use of a refresh token by revoking the whole family.
/// A token M1 refused is remembered and not sent again, so a tab sitting on a dead
/// session costs one read rather than one per poll. A read that cannot decide ends
/// the wait and takes nothing: a throttle, M1 down, or an answer with no verdict in
/// it.
fn confirm_candidate(
    candidate: &Captured,
    refused: &Mutex<Option<Secret>>,
    prove: impl FnOnce(&TokenBundle) -> Result<(), CliError>,
) -> Confirm {
    const DEAD: &str = "M1 refused the session this window holds, and no new sign-in has finished";
    let Some(value) = candidate.value() else {
        return Confirm::NotYet("the page held no session".into());
    };
    let bundle = match auth0::parse_browser_capture(value.expose()) {
        Ok(bundle) => bundle,
        Err(e) => return Confirm::NotYet(e.to_string()),
    };
    if expiry_passed(&bundle) {
        return Confirm::NotYet(
            "the session this window holds has expired, and no new sign-in has finished".into(),
        );
    }
    let mut refused = refused.lock().unwrap_or_else(|e| e.into_inner());
    if refused
        .as_ref()
        .is_some_and(|token| token.expose() == bundle.access_token)
    {
        return Confirm::NotYet(DEAD.into());
    }
    match prove(&bundle) {
        Ok(()) => Confirm::Ready,
        Err(CliError::Auth(_)) => {
            *refused = Some(Secret::new(bundle.access_token.clone()));
            Confirm::NotYet(DEAD.into())
        }
        Err(e) => Confirm::Fail(e),
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
    read_viewer(&ctx.cfg.base_url(), ctx.common.verbose, bundle)
}

/// [`verify`] without the [`Ctx`], so the capture's confirm hook can own what
/// it needs. Bounded by the HTTP client's 60 s timeout, which also bounds the
/// hook.
fn read_viewer(endpoint: &str, verbose: bool, bundle: &TokenBundle) -> Result<(), CliError> {
    let client = M1Client::new(endpoint, Some(bundle.access_token.clone()), verbose)?;
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
    let mut status = status_dto(ctx, bundle.as_ref(), ctx.cfg.username.as_deref());
    status.browser_profile = browser_profile_status(ctx.creds, ctx.common.quiet, || {
        pk_cli_browser::profile_exists(crate::BIN)
    });
    status.emit(ctx.common.json);
    Ok(())
}

/// `auth status`'s browser field: whether a `--browser` sign-in keeps a profile
/// here. A kept profile, not a signed-in one. A keychain pointed away from the real
/// session signs in from a scratch profile, so it reports none and reads nothing of
/// the real one's. `auth status` works whatever state the CLI is in, so a profile
/// that needs repair is a warning and leaves the field out. The check is passed in:
/// the binary binds `profile_exists`, the tests `profile_exists_in` under a temp dir.
fn browser_profile_status(
    creds: &CredentialStore,
    quiet: bool,
    exists: impl FnOnce() -> Result<bool, BrowserError>,
) -> Option<bool> {
    if keychain_redirected(creds) {
        return None;
    }
    match exists() {
        Ok(kept) => Some(kept),
        Err(e) => {
            if !quiet {
                eprintln!("warning: {e}");
            }
            None
        }
    }
}

pub fn logout(ctx: &Ctx, store: &ConfigStore, args: &LogoutArgs) -> Result<(), CliError> {
    let done = run_logout(
        ctx.creds,
        args.forget,
        || ctx.forget_tokens(),
        || ctx.clear_pending(),
        || store.clear().map(|_| ()),
        || pk_cli_browser::forget_profile(crate::BIN),
    )?;
    if !ctx.common.quiet {
        eprintln!("{done}");
        eprintln!(
            "note: this clears the local copy only — to end the session at M1, change \
             your password or sign out other devices in M1's own app"
        );
    }
    Ok(())
}

/// `auth logout`'s steps, each attempted whatever an earlier one did: one that
/// fails must not leave a session behind in the others. If any fails, the error
/// says what is cleared and what remains, with the first failure's exit code.
/// Otherwise this is the status line.
///
/// The steps are passed in so a test can fail any of them and reach neither the
/// keychain nor the owner's real profile: the binary binds the last to
/// `forget_profile(BIN)`, the tests to `forget_profile_in` under a temp dir. That
/// profile holds M1's cookies, browsing history and cache, so a logout removes it
/// and the next sign-in starts signed out.
///
/// With `M1F_KEYCHAIN_SERVICE` set, this logout clears some other service's
/// tokens, and the real session is still there. The profile and the config have no
/// such variable, so both are left alone, and the line says so.
fn run_logout(
    creds: &CredentialStore,
    forgot: bool,
    session: impl FnOnce() -> Result<(), CliError>,
    pending: impl FnOnce() -> Result<(), CliError>,
    identity: impl FnOnce() -> Result<(), CliError>,
    forget_profile: impl FnOnce() -> Result<bool, BrowserError>,
) -> Result<String, CliError> {
    let mut steps = LogoutSteps::default();
    steps.session(session());
    if let Err(e) = pending() {
        steps.failed("a half-finished login", e);
    }
    let redirected = keychain_redirected(creds);
    if forgot && !redirected {
        steps.step("the config identity", identity());
    }
    let removed = if redirected {
        steps.remains(
            "the browser profile and the config, left because M1F_KEYCHAIN_SERVICE is set",
        );
        false
    } else {
        steps.browser(forget_profile)
    };
    let finish = format!(
        "{} auth logout{}",
        crate::BIN,
        if forgot { " --forget" } else { "" }
    );
    steps.report(&finish)?;
    Ok(if redirected {
        format!(
            "logged out of keychain service `{}` (stored tokens cleared); browser profile and \
             config left in place, because M1F_KEYCHAIN_SERVICE is set",
            creds.service()
        )
    } else {
        format!(
            "logged out (stored tokens cleared{})",
            if removed {
                "; browser profile removed"
            } else {
                ""
            }
        )
    })
}

/// What a logout got done so far.
#[derive(Default)]
struct LogoutSteps {
    cleared: Vec<String>,
    remains: Vec<String>,
    reasons: Vec<String>,
    first: Option<CliError>,
    finish_when: Option<&'static str>,
}

impl LogoutSteps {
    /// The session's removal. `Upstream` is the refresh lock's: the delete has run,
    /// and what remains is a renewal in flight that can store the session again.
    fn session(&mut self, result: Result<(), CliError>) {
        let what = match &result {
            Err(CliError::Upstream(_)) => {
                self.finish_when = Some("In a minute, run");
                "a renewal that can store the session again"
            }
            _ => "the stored session",
        };
        self.step(what, result);
    }

    fn step(&mut self, what: &str, result: Result<(), CliError>) {
        match result {
            Ok(()) => self.cleared.push(what.to_string()),
            Err(e) => self.failed(what, e),
        }
    }

    fn failed(&mut self, what: &str, error: CliError) {
        self.remains(what);
        self.reasons
            .push(inner_message(&error).trim_end_matches('.').to_string());
        self.first.get_or_insert(error);
    }

    fn remains(&mut self, what: &str) {
        self.remains.push(what.to_string());
    }

    /// The profile's removal; `true` when there was one to remove.
    fn browser(&mut self, forget: impl FnOnce() -> Result<bool, BrowserError>) -> bool {
        match forget() {
            Ok(removed) => {
                if removed {
                    self.cleared.push("the browser profile".to_string());
                }
                removed
            }
            Err(e) => {
                self.finish_when = Some(match e {
                    BrowserError::ProfileInUse(_) => "Once that window is closed, run",
                    _ => "Repair or delete that path, then run",
                });
                self.failed("the browser profile", e.into());
                false
            }
        }
    }

    fn report(self, finish: &str) -> Result<(), CliError> {
        let Some(first) = self.first else {
            return Ok(());
        };
        let cleared = match self.cleared.len() {
            0 => "nothing is cleared".to_string(),
            1 => format!("{} is cleared", self.cleared[0]),
            _ => format!("{} are cleared", listed(&self.cleared)),
        };
        let remains = match self.remains.len() {
            1 => format!("only {} remains", self.remains[0]),
            _ => format!("{} remain", listed(&self.remains)),
        };
        let when = match self.reasons.len() {
            1 => self.finish_when.unwrap_or("Fix that, then run"),
            _ => "Fix those, then run",
        };
        let reasons = self.reasons.join(". ");
        let message = format!(
            "partly logged out: {cleared} and {remains}. {reasons}. {when} `{finish}` again to \
             finish."
        );
        // The exit code is the first failure's. `Keychain` and `Other` share theirs,
        // and `Other` puts no "keychain error:" in front of the whole report. A held
        // refresh lock is `Upstream`: exit 5 comes only with that variant's prefix.
        Err(match first {
            CliError::Keychain(_) => CliError::Other(message),
            first => reworded(first, |_| message),
        })
    }
}

/// A failure's own message, without the prefix its `Display` puts on.
fn inner_message(error: &CliError) -> &str {
    match error {
        CliError::Usage(m)
        | CliError::Auth(m)
        | CliError::NotFound(m)
        | CliError::Upstream(m)
        | CliError::ConfirmationRequired(m)
        | CliError::Keychain(m)
        | CliError::Other(m) => m,
    }
}

fn listed(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
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
    ctx.lock_usable()?;
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

    /// A session the kept profile holds, as the capture would read it.
    fn held(access_token: &str) -> Captured {
        let entry = crate::auth0::tests::cache_entry(access_token).to_string();
        Captured::for_test("M1", crate::auth0::DASHBOARD_HOST)
            .value(entry)
            .build()
    }

    fn live_token() -> String {
        let claims = crate::auth0::tests::m1_claims(4_102_444_800);
        crate::auth0::tests::jwt(claims)
    }

    /// An expired session keeps the tab open, with no read and no renewal.
    #[test]
    fn an_expired_session_keeps_the_tab_open() {
        let expired = crate::auth0::tests::jwt(crate::auth0::tests::m1_claims(1));
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&expired), &refused, |_| {
            panic!("an expired session must not reach M1")
        });
        match answer {
            Confirm::NotYet(reason) => assert!(reason.contains("expired"), "{reason}"),
            other => panic!("must keep waiting: {other:?}"),
        }
    }

    #[test]
    fn a_session_m1_accepts_closes_the_tab() {
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&live_token()), &refused, |_| Ok(()));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
    }

    /// A live-looking session M1 refuses keeps the tab open for the owner to
    /// sign in, and is read once however many polls see it. The session that
    /// replaces it is read.
    #[test]
    fn a_refused_session_waits_and_is_not_sent_again() {
        use std::cell::Cell;
        let reads = Cell::new(0);
        let prove = |answer: Result<(), CliError>| {
            reads.set(reads.get() + 1);
            answer
        };
        let refused = Mutex::new(None);
        let dead = live_token();
        for _ in 0..3 {
            let answer = confirm_candidate(&held(&dead), &refused, |_| {
                prove(Err(CliError::Auth("dummy refusal".into())))
            });
            match answer {
                Confirm::NotYet(reason) => assert!(reason.contains("refused"), "{reason}"),
                other => panic!("must keep waiting: {other:?}"),
            }
        }
        assert_eq!(reads.get(), 1, "the dead token was sent again");

        let renewed = crate::auth0::tests::jwt(crate::auth0::tests::m1_claims(4_102_444_801));
        let answer = confirm_candidate(&held(&renewed), &refused, |_| prove(Ok(())));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
        assert_eq!(reads.get(), 2);
    }

    #[test]
    fn a_failure_waiting_will_not_fix_ends_the_wait() {
        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&live_token()), &refused, |_| {
            Err(CliError::Upstream("dummy outage".into()))
        });
        match answer {
            Confirm::Fail(e) => assert_eq!(e.exit_code(), 5),
            other => panic!("must end the wait: {other:?}"),
        }
    }

    #[test]
    fn a_window_with_nothing_readable_keeps_waiting() {
        let refused = Mutex::new(None);
        let none = Captured::for_test("M1", crate::auth0::DASHBOARD_HOST).build();
        let junk = Captured::for_test("M1", crate::auth0::DASHBOARD_HOST)
            .value("not a session")
            .build();
        for candidate in [none, junk] {
            let answer = confirm_candidate(&candidate, &refused, |_| panic!("nothing to read yet"));
            assert!(matches!(answer, Confirm::NotYet(_)), "{answer:?}");
        }
    }

    /// The kept profile's directory for `root`, with something in it.
    fn kept_profile(root: &std::path::Path) -> std::path::PathBuf {
        let profile = root
            .join(format!("piekstra.{}", crate::BIN))
            .join("browser-profile");
        std::fs::create_dir_all(profile.join("Default")).unwrap();
        profile
    }

    /// The logout's browser step on a temp dir through `test-util`'s
    /// `forget_profile_in`, so a test never removes the owner's real profile.
    #[test]
    fn logout_removes_the_kept_browser_profile() {
        let root = tempfile::tempdir().unwrap();
        let profile = kept_profile(root.path());
        let forget = || pk_cli_browser::forget_profile_in(root.path(), crate::BIN);
        assert_eq!(
            logout_with(false, forget).unwrap(),
            "logged out (stored tokens cleared; browser profile removed)"
        );
        assert!(!profile.exists());
        // The parent is the CLI's, and stays.
        assert!(profile.parent().unwrap().exists());
    }

    #[test]
    fn logout_with_no_kept_profile_still_logs_out() {
        let root = tempfile::tempdir().unwrap();
        let forget = || pk_cli_browser::forget_profile_in(root.path(), crate::BIN);
        assert_eq!(
            logout_with(false, forget).unwrap(),
            "logged out (stored tokens cleared)"
        );
    }

    /// A script that stands in for Chrome: it writes to the profile's site storage
    /// as a page would, reports a debug port and sleeps until stopped. It is what a
    /// launch runs in these tests, so the real lock and removals are exercised and no
    /// Chrome starts.
    #[cfg(unix)]
    fn stand_in_chrome(dir: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("stand-in-chrome");
        std::fs::write(
            &path,
            "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in --user-data-dir=*) \
             d=\"${a#--user-data-dir=}\";; esac; done\n\
             mkdir -p \"$d/Default/Local Storage\"\n\
             : > \"$d/Default/Local Storage/from-this-run\"\n\
             printf '1\\n/devtools/browser/dummy\\n' > \"$d/DevToolsActivePort\"\n\
             exec sleep 60\n",
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// What `m1f` builds for a sign-in, running the stand-in under `root`.
    #[cfg(unix)]
    fn launch_under(root: &std::path::Path, chrome: &std::path::Path) -> Launch {
        browser_launch(false, true, "dummy-hint".to_string())
            .chrome(chrome)
            .ctrl_c(false)
            .profile_root(root)
    }

    /// What an earlier run left in site storage is gone before Chrome starts, what
    /// this run wrote is gone once it has stopped, and the cookies stay.
    #[cfg(unix)]
    #[test]
    fn a_kept_profile_keeps_its_cookies_and_never_its_site_storage() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let chrome = stand_in_chrome(tools.path());
        drop(launch_under(root.path(), &chrome).spawn().unwrap());
        let default = root
            .path()
            .join(format!("piekstra.{}", crate::BIN))
            .join("browser-profile/Default");
        let left_behind = default.join("Local Storage/leveldb");
        std::fs::create_dir_all(&left_behind).unwrap();
        std::fs::write(left_behind.join("000003.log"), "dummy").unwrap();
        std::fs::write(default.join("Cookies"), "dummy").unwrap();

        let running = launch_under(root.path(), &chrome).spawn().unwrap();
        assert!(!left_behind.exists(), "cleared before Chrome starts");
        assert!(default.join("Local Storage/from-this-run").exists());
        drop(running);
        assert!(!default.join("Local Storage").exists(), "and once it stops");
        assert!(default.join("Cookies").exists());
    }

    /// `auth status` says whether a profile is kept, and a path that needs repair
    /// is a warning that leaves the field out, never a failed status.
    #[cfg(unix)]
    #[test]
    fn auth_status_reports_the_kept_profile() {
        let root = tempfile::tempdir().unwrap();
        let exists = || pk_cli_browser::profile_exists_in(root.path(), crate::BIN);
        let field = || browser_profile_status(&real_store(), true, exists);
        assert_eq!(field(), Some(false));

        let parent = root.path().join(format!("piekstra.{}", crate::BIN));
        let profile = parent.join("browser-profile");
        std::fs::create_dir_all(&profile).unwrap();
        assert_eq!(field(), Some(true));
        let mut status = AuthStatus::new(true, false, AuthMethod::BrowserSession);
        status.browser_profile = field();
        assert_eq!(status.to_json()["browser_profile"], true);

        std::fs::remove_dir(&profile).unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), &profile).unwrap();
        assert_eq!(field(), None);
        status.browser_profile = field();
        assert!(status.to_json().get("browser_profile").is_none());
    }

    /// A keychain pointed away from the real session has no kept profile of its
    /// own, and does not read the real one's.
    #[test]
    fn a_redirected_keychain_reports_no_kept_profile() {
        let elsewhere = CredentialStore::new("m1f-dummy-service");
        let field = browser_profile_status(&elsewhere, true, || {
            panic!("a redirected keychain must not look at the real profile")
        });
        assert_eq!(field, None);
    }

    /// A profile a sign-in is using is refused, exit 1, and left alone, and the
    /// error says what is already gone and how to finish. A real sign-in holds it
    /// here, through a stand-in for Chrome that reports a debug port and sleeps,
    /// so the real lock is what refuses. No Chrome starts.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_a_kept_profile_a_sign_in_is_using() {
        let root = tempfile::tempdir().unwrap();
        let tools = tempfile::tempdir().unwrap();
        let stand_in = stand_in_chrome(tools.path());
        let signing_in = launch_under(root.path(), &stand_in).spawn().unwrap();

        let forget = || pk_cli_browser::forget_profile_in(root.path(), crate::BIN);
        let err = logout_with(false, forget).unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        for needle in [
            "the stored session is cleared",
            "only the browser profile remains",
            "log out again",
            "Once that window is closed",
            "`m1f auth logout` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
        let profile = root
            .path()
            .join(format!("piekstra.{}", crate::BIN))
            .join("browser-profile");
        assert!(profile.exists(), "a profile in use must be left alone");

        drop(signing_in);
        let forget = || pk_cli_browser::forget_profile_in(root.path(), crate::BIN);
        assert_eq!(
            logout_with(false, forget).unwrap(),
            "logged out (stored tokens cleared; browser profile removed)"
        );
        assert!(!profile.exists());
    }

    /// `CredentialStore` touches the keychain only when read or written, so
    /// these never do.
    fn real_store() -> CredentialStore {
        CredentialStore::for_binary(crate::BIN)
    }

    /// The failures a sign-in can end in once Chrome has run in the profile,
    /// with the exit code each must keep.
    fn window_failures() -> Vec<(BrowserError, i32)> {
        vec![
            (BrowserError::TimedOut("dummy.".into()), 3),
            (BrowserError::WindowClosed("dummy.".into()), 3),
            (BrowserError::Canceled, 1),
            (BrowserError::Launch("dummy.".into()), 1),
            (
                BrowserError::Handler(CliError::Upstream("dummy.".into())),
                5,
            ),
            (BrowserError::Handler(CliError::Auth("dummy.".into())), 3),
        ]
    }

    fn assert_says_it_stays(err: &CliError) {
        if cfg!(unix) {
            let message = err.to_string();
            assert!(
                message.contains("browser profile stays on disk"),
                "{message}"
            );
            assert!(message.contains("`m1f auth logout`"), "{message}");
        }
    }

    /// Every way a sign-in can fail with Chrome in the kept profile says so,
    /// whichever step failed, and keeps its exit code. A scratch profile is
    /// already gone, so it says nothing.
    #[test]
    fn every_failed_sign_in_says_the_kept_profile_stays() {
        for (error, code) in window_failures() {
            let err = through_the_window(false, || Err(error), |_| panic!("no session to store"))
                .unwrap_err();
            assert_eq!(err.exit_code(), code, "{err}");
            assert_says_it_stays(&err);
        }
        for (error, code) in window_failures() {
            let err = through_the_window(true, || Err(error), |_| panic!("no session to store"))
                .unwrap_err();
            assert_eq!(err.exit_code(), code, "{err}");
            assert!(!err.to_string().contains("stays on disk"), "{err}");
        }
    }

    /// After the capture the session is read and stored, and a live session can
    /// be left in the profile if that fails.
    #[test]
    fn a_failure_after_the_capture_says_the_kept_profile_stays() {
        for (failure, code) in [
            (CliError::Keychain("dummy: could not write".into()), 1),
            (CliError::Upstream("dummy outage".into()), 5),
            (CliError::Auth("dummy refusal".into()), 3),
        ] {
            let captured = held(&live_token());
            let err = through_the_window(false, || Ok(captured), |_| Err(failure)).unwrap_err();
            assert_eq!(err.exit_code(), code, "{err}");
            assert_says_it_stays(&err);
        }
        let empty = Captured::for_test("M1", crate::auth0::DASHBOARD_HOST).build();
        let err =
            through_the_window(false, || Ok(empty), |_| panic!("nothing was read")).unwrap_err();
        assert_says_it_stays(&err);

        let captured = held(&live_token());
        let err = through_the_window(
            true,
            || Ok(captured),
            |_| Err(CliError::Keychain("dummy: could not write".into())),
        )
        .unwrap_err();
        assert!(!err.to_string().contains("stays on disk"), "{err}");

        let captured = held(&live_token());
        through_the_window(false, || Ok(captured), |_| Ok(())).unwrap();
    }

    /// These end the sign-in before Chrome runs in the profile.
    #[test]
    fn a_failure_before_chrome_runs_does_not_mention_the_profile_staying() {
        for error in [
            BrowserError::ChromeNotFound("dummy".into()),
            BrowserError::Invalid("dummy".into()),
            BrowserError::Profile("dummy".into()),
            BrowserError::ProfileInUse("dummy".into()),
        ] {
            let err = through_the_window(false, || Err(error), |_| panic!("no session to store"))
                .unwrap_err();
            assert_eq!(err.exit_code(), 1, "{err}");
            assert!(!err.to_string().contains("stays on disk"), "{err}");
        }
    }

    /// The note changes the message and never the exit code.
    #[test]
    fn the_note_keeps_every_exit_code() {
        for (error, code) in [
            (CliError::Usage("dummy.".into()), 2),
            (CliError::Auth("dummy.".into()), 3),
            (CliError::NotFound("dummy.".into()), 4),
            (CliError::Upstream("dummy.".into()), 5),
            (CliError::ConfirmationRequired("dummy.".into()), 6),
            (CliError::Keychain("dummy.".into()), 1),
            (CliError::Other("dummy.".into()), 1),
        ] {
            let err = failed_sign_in(error, false);
            assert_eq!(err.exit_code(), code, "{err}");
            assert_says_it_stays(&err);
            if cfg!(unix) {
                assert!(err.to_string().contains("dummy. The browser"), "{err}");
            }
        }
    }

    /// The hook against real answers: a throttle or an outage ends the wait
    /// rather than loop on it, a refusal keeps the tab open, and only a `true`
    /// closes it. Neither of the first two is remembered as a refused token.
    #[test]
    fn a_read_that_cannot_decide_ends_the_wait_and_accepts_nothing() {
        const PAGE: &str = "<!DOCTYPE html><html><title>Just a moment...</title></html>";
        let read = |status: u16, body: &str| {
            crate::client::tests::read_answer(status, body).and_then(|data| verdict(&data))
        };
        let accepted = r#"{"data":{"viewer":{"isAuthenticated":true}}}"#;
        let declined = r#"{"data":{"viewer":{"isAuthenticated":false}}}"#;
        let token = live_token();

        for (status, body) in [
            (429, PAGE),
            (429, "{}"),
            (429, accepted),
            (500, "{}"),
            (502, "bad gateway"),
            (503, PAGE),
            (503, accepted),
            (200, ""),
            (200, "null"),
            (200, "{}"),
            (200, r#"{"data":null}"#),
            (200, r#"{"data":{}}"#),
            (200, r#"{"data":{"viewer":null}}"#),
            (200, r#"{"data":{"viewer":{}}}"#),
            (200, r#"{"data":{"viewer":{"isAuthenticated":"true"}}}"#),
        ] {
            let refused = Mutex::new(None);
            let answer = confirm_candidate(&held(&token), &refused, |_| read(status, body));
            match answer {
                Confirm::Fail(e) => assert_eq!(e.exit_code(), 5, "{status} {body}: {e}"),
                other => panic!("{status} {body} must end the wait: {other:?}"),
            }
            assert!(refused.lock().unwrap().is_none(), "{status} {body}");
        }

        for (status, body) in [
            (401, "{}"),
            (403, "{}"),
            (403, PAGE),
            (200, PAGE),
            (200, declined),
        ] {
            let refused = Mutex::new(None);
            let answer = confirm_candidate(&held(&token), &refused, |_| read(status, body));
            assert!(
                matches!(answer, Confirm::NotYet(_)),
                "{status} {body}: {answer:?}"
            );
            assert!(refused.lock().unwrap().is_some(), "{status} {body}");
        }

        let refused = Mutex::new(None);
        let answer = confirm_candidate(&held(&token), &refused, |_| read(200, accepted));
        assert!(matches!(answer, Confirm::Ready), "{answer:?}");
    }

    /// `M1F_KEYCHAIN_SERVICE` moves the keychain, not the profile: a logout under
    /// it must never reach the real one, and says it left it.
    #[test]
    fn a_redirected_keychain_leaves_the_real_profile_alone() {
        let elsewhere = CredentialStore::new("m1f-dummy-service");
        assert!(keychain_redirected(&elsewhere));
        assert!(!keychain_redirected(&real_store()));

        let line = run_logout(
            &elsewhere,
            true,
            || Ok(()),
            || Ok(()),
            || panic!("a logout under a redirected keychain must not touch the config"),
            || panic!("a logout under a redirected keychain must not touch the profile"),
        )
        .unwrap();
        for needle in [
            "m1f-dummy-service",
            "browser profile and config left in place",
            "M1F_KEYCHAIN_SERVICE",
        ] {
            assert!(line.contains(needle), "missing {needle:?} in: {line}");
        }

        // Naming the real service is the real logout.
        let same = CredentialStore::new(real_store().service().to_string());
        let line = run_logout(&same, false, || Ok(()), || Ok(()), || Ok(()), || Ok(true)).unwrap();
        assert!(line.contains("browser profile removed"), "{line}");

        // A failure under it still never reaches the profile, and says it stayed.
        let err = run_logout(
            &elsewhere,
            false,
            || Err(CliError::Keychain("dummy: could not delete".into())),
            || Ok(()),
            || Ok(()),
            || panic!("a logout under a redirected keychain must not touch the profile"),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(message.contains("M1F_KEYCHAIN_SERVICE"), "{message}");
    }

    /// Logout with every step but the profile's succeeding.
    fn logout_with(
        forgot: bool,
        forget: impl FnOnce() -> Result<bool, BrowserError>,
    ) -> Result<String, CliError> {
        run_logout(
            &real_store(),
            forgot,
            || Ok(()),
            || Ok(()),
            || Ok(()),
            forget,
        )
    }

    /// A step that fails stops nothing: every later step still runs, and the
    /// error says what is cleared and what remains.
    #[test]
    fn a_failed_logout_step_stops_nothing() {
        use std::cell::RefCell;
        let keychain = || Err(CliError::Keychain("dummy: could not delete".into()));
        let config = || Err(CliError::Other("dummy: could not write".into()));
        let ok = || Ok(());

        type Step = fn() -> Result<(), CliError>;
        type Case = (
            Step,
            Step,
            Step,
            &'static [&'static str],
            &'static [&'static str],
        );
        let cases: [Case; 3] = [
            (
                keychain,
                ok,
                ok,
                &["the config identity", "the browser profile"],
                &["only the stored session remains"],
            ),
            (
                ok,
                keychain,
                ok,
                &[
                    "the stored session",
                    "the config identity",
                    "the browser profile",
                ],
                &["only a half-finished login remains"],
            ),
            (
                ok,
                ok,
                config,
                &["the stored session", "the browser profile"],
                &["only the config identity remains"],
            ),
        ];
        for (session, pending, identity, cleared, remains) in cases {
            let ran = RefCell::new(Vec::new());
            let track = |step: &'static str, run: Step| {
                ran.borrow_mut().push(step);
                run()
            };
            let err = run_logout(
                &real_store(),
                true,
                || track("session", session),
                || track("pending", pending),
                || track("identity", identity),
                || {
                    ran.borrow_mut().push("profile");
                    Ok(true)
                },
            )
            .unwrap_err();
            assert_eq!(
                *ran.borrow(),
                ["session", "pending", "identity", "profile"],
                "{err}"
            );
            assert_eq!(err.exit_code(), 1, "{err}");
            let message = err.to_string();
            for needle in cleared.iter().chain(remains) {
                assert!(message.contains(needle), "missing {needle:?} in: {message}");
            }
            for needle in ["dummy: could not", "`m1f auth logout --forget` again"] {
                assert!(message.contains(needle), "missing {needle:?} in: {message}");
            }
            // Built from the inner messages, with no prefix in front or inside.
            assert!(message.starts_with("partly logged out: "), "{message}");
            assert!(!message.contains("keychain error"), "{message}");
        }
    }

    /// The exit code is the first failure's, and every failure is named.
    #[test]
    fn a_failed_logout_exits_with_the_first_failures_code() {
        let err = run_logout(
            &real_store(),
            false,
            || Err(CliError::Auth("dummy first".into())),
            || Ok(()),
            || panic!("--forget was not asked for"),
            || Err(BrowserError::ProfileInUse("dummy second".into())),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 3, "{err}");
        let message = err.to_string();
        assert!(message.starts_with("partly logged out: "), "{message}");
        for needle in [
            "nothing is cleared",
            "the stored session and the browser profile remain",
            "dummy first",
            "dummy second",
            "Fix those, then run `m1f auth logout` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }

        // A refresh lock held past the wait: the prefix once, and not inside.
        let err = run_logout(
            &real_store(),
            false,
            || Err(CliError::Upstream("dummy: lock held".into())),
            || Err(CliError::Keychain("dummy second".into())),
            || panic!("--forget was not asked for"),
            || Ok(true),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5, "{err}");
        let message = err.to_string();
        assert_eq!(
            message.matches("network/upstream error").count(),
            1,
            "{message}"
        );
        assert!(!message.contains("keychain error"), "{message}");

        // On its own: the tokens are gone, so the report does not say they remain.
        let err = run_logout(
            &real_store(),
            false,
            || Err(CliError::Upstream("dummy: lock held".into())),
            || Ok(()),
            || panic!("--forget was not asked for"),
            || Ok(true),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 5, "{err}");
        let message = err.to_string();
        assert!(
            message.contains("only a renewal that can store the session again remains"),
            "{message}"
        );
        assert!(!message.contains("stored session remains"), "{message}");
        assert!(
            message.contains("In a minute, run `m1f auth logout`"),
            "{message}"
        );

        let err = run_logout(
            &real_store(),
            false,
            || Ok(()),
            || Ok(()),
            || panic!("--forget was not asked for"),
            || Err(BrowserError::Profile("dummy".into())),
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
    }

    /// A sign-in on a keychain pointed elsewhere leaves the real config alone.
    #[test]
    fn a_redirected_keychain_writes_no_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let store = ConfigStore::new(crate::BIN).with_override(Some(path.clone()));

        let elsewhere = CredentialStore::new("m1f-dummy-service");
        remember_username(&elsewhere, &store, "owner@example.invalid").unwrap();
        assert!(!path.exists(), "the real config must not be written");

        remember_username(&real_store(), &store, "owner@example.invalid").unwrap();
        let saved: Config = store.load().unwrap();
        assert_eq!(saved.username.as_deref(), Some("owner@example.invalid"));
    }

    /// A keychain pointed elsewhere signs in through a scratch profile too, so
    /// it cannot read the real session out of the kept one.
    #[test]
    fn a_redirected_keychain_signs_in_from_a_scratch_profile() {
        let parse = |flags: &[&str]| {
            let mut argv = vec!["test"];
            argv.extend_from_slice(flags);
            <LoginCmdArgs as clap::Args>::augment_args(clap::Command::new("test"))
                .try_get_matches_from(argv)
                .and_then(|m| <LoginCmdArgs as clap::FromArgMatches>::from_arg_matches(&m))
                .unwrap()
        };
        let elsewhere = CredentialStore::new("m1f-dummy-service");
        assert!(scratch_profile(&elsewhere, &parse(&["--browser"])));
        assert!(!scratch_profile(&real_store(), &parse(&["--browser"])));
        assert!(scratch_profile(
            &real_store(),
            &parse(&["--browser", "--fresh-profile"])
        ));
    }

    /// A profile that needs repair is refused, not followed: a symlink's
    /// target survives the logout's refusal.
    #[cfg(unix)]
    #[test]
    fn logout_refuses_a_kept_profile_that_needs_repair() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let profile = root
            .path()
            .join(format!("piekstra.{}", crate::BIN))
            .join("browser-profile");
        std::fs::create_dir_all(profile.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), &profile).unwrap();
        let forget = || pk_cli_browser::forget_profile_in(root.path(), crate::BIN);
        let err = logout_with(true, forget).unwrap_err();
        assert_eq!(err.exit_code(), 1, "{err}");
        let message = err.to_string();
        for needle in [
            "the stored session and the config identity are cleared",
            "only the browser profile remains",
            "symlink",
            "Repair or delete that path",
            "`m1f auth logout --forget` again",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in: {message}");
        }
        assert!(elsewhere.path().exists());
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
        // `--browser-session` beside `--browser` means the same as alone.
        assert_eq!(
            parse(&["--browser", "--browser-session", "--fresh-profile"]).retry_hint(),
            format!("{} --fresh-profile", crate::auth0::LOGIN)
        );
        // A retry stays in the scratch profile it was asked to use.
        assert_eq!(
            parse(&["--browser", "--overwrite", "--fresh-profile"]).retry_hint(),
            format!("{} --fresh-profile", crate::auth0::RELOGIN)
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
