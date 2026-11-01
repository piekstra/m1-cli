//! `m1f` — a read-only CLI over M1's (m1.com) investment platform.
//!
//! Conforms to the piekstra-cli/1 spec (see cli-common/DESIGN.md). This module
//! owns the clap tree and the exit-code mapping; everything else lives in
//! `client` (GraphQL transport), `graphql` (documents + read-only guard),
//! `config` (non-secret settings), and `commands/*`.
//!
//! M1 publishes no official API. See `docs/api.md` for what is verified and
//! what is not.

mod auth0;
mod client;
mod commands;
mod config;
mod graphql;
mod parse;

use std::path::PathBuf;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use pk_cli_auth::{LogoutArgs, SetCredentialArgs};
use pk_cli_config::ConfigStore;
use pk_cli_core::info::{AuthInfo, CliInfo};
use pk_cli_core::{output, CliError, CommonArgs, RangeArgs};
use pk_cli_secrets::CredentialStore;
use pk_cli_selfupdate::{SelfUpdateArgs, Updater};

pub const BIN: &str = "m1f";
pub const REPO: &str = "piekstra/m1-cli";

/// Read M1 investment accounts, holdings, activity, and tax documents.
///
/// Unofficial: not affiliated with or endorsed by M1 Holdings. Read-only.
#[derive(Parser, Debug)]
#[command(name = BIN, version, about, long_about = None)]
struct Cli {
    #[command(flatten)]
    common: CommonArgs,

    /// Account id to act on (see `m1f accounts list`).
    #[arg(short = 'a', long, global = true, env = "M1F_ACCOUNT")]
    account: Option<String>,

    /// Override the config file location.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Credential management and session status.
    #[command(subcommand)]
    Auth(AuthCmd),
    /// Non-secret settings.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Investment accounts.
    #[command(subcommand)]
    Accounts(AccountsCmd),
    /// Positions held in an account (every account when none is selected).
    #[command(subcommand)]
    Holdings(HoldingsCmd),
    /// Positions across every account, family position-list/v1 shape.
    #[command(subcommand)]
    Positions(PositionsCmd),
    /// Dividend payments across every account, family dividend-list/v1 shape.
    #[command(subcommand)]
    Dividends(DividendsCmd),
    /// Account activity: trades, dividends, transfers.
    #[command(subcommand)]
    Activity(ActivityCmd),
    /// Statements and tax forms (documents/v1 profile).
    #[command(subcommand)]
    Documents(DocumentsCmd),
    /// Per-lot cost basis and wash-sale data (Form 8949 detail).
    #[command(subcommand)]
    Lots(LotsCmd),
    /// Normalized per-transaction ledger (FDX), richest for tax work.
    #[command(subcommand)]
    Transactions(TransactionsCmd),
    /// Money movements: deposits, withdrawals, transfers.
    #[command(subcommand)]
    Transfers(TransfersCmd),
    /// Household net worth across every M1 product line.
    NetWorth,
    /// IRA contribution room by year (for an IRA account).
    Ira,
    /// Per-account snapshot: value, cost, unrealized gain %, funding.
    Summary,
    /// M1's own system status — no login required.
    Status,
    /// Raw GraphQL passthrough (read-only).
    #[command(subcommand)]
    Api(ApiCmd),
    /// Update to the latest release from GitHub.
    SelfUpdate(SelfUpdateArgs),
    /// Print a shell completion script.
    Completions { shell: Shell },
    /// Machine-readable capability discovery (cli-info/v1).
    Info,
}

#[derive(Subcommand, Debug)]
enum AuthCmd {
    /// Log in and store the session in the OS keychain.
    ///
    /// Since 2026-10-27 M1's Cloudflare front answers the password login with
    /// an HTTP 403 page; M1's own web app signs in through Auth0 instead. So
    /// m1f takes the session the web app keeps:
    ///
    ///   m1f auth login --browser
    ///
    /// opens a Chrome window, with a throwaway profile, at
    /// https://dashboard.m1.com. Sign in there as usual: the password and any
    /// emailed code go to M1's page, never to m1f. Once you are in, m1f reads
    /// the session from the dashboard's localStorage, closes the tab at once
    /// (so the web app cannot rotate the refresh token it just handed over),
    /// quits Chrome and deletes the profile. It checks the session with one
    /// read before storing it, then renews it on its own. The wait is up to
    /// 10 minutes; Ctrl-C cancels. Set M1F_CHROME to a Chrome binary that is
    /// not in a standard place. Pass --overwrite to replace a stored session.
    ///
    /// Without Chrome, copy the session out of any browser and pipe it in
    /// (--browser-session):
    ///
    ///   1. Open a private (incognito) window at https://dashboard.m1.com and
    ///      sign in as usual (password and any code happen on M1's page).
    ///
    ///   2. Open DevTools (Cmd-Opt-I, or F12) → Console, and run:
    ///
    ///      copy(localStorage[Object.keys(localStorage).find(k => k.startsWith('@@auth0spajs@@::') && k.includes('lens.m1finance.com'))])
    ///
    ///      (Or by hand: Application → Local storage → https://dashboard.m1.com,
    ///      the key starting `@@auth0spajs@@::` and containing
    ///      `lens.m1finance.com`; copy its value. A request's `Authorization:
    ///      Bearer …` header from the Network tab also works, but carries no
    ///      refresh token, so it lasts only until it expires.)
    ///
    ///   3. In a terminal:  pbpaste | m1f auth login --browser-session --stdin
    ///
    ///   4. Close the private window without signing out. Auth0 may rotate the
    ///      refresh token on each renewal; a browser still holding the old one
    ///      would use it later, and Auth0 answers that reuse by revoking the
    ///      session for both.
    ///
    /// Both routes store the same session. The password login (neither flag)
    /// is kept for when the edge lets it through again: if M1 answers with a
    /// verification challenge, finish with `m1f auth login --code <CODE>`.
    Login(commands::auth::LoginCmdArgs),
    /// Report credential/session state (auth-status/v1).
    Status,
    /// Clear the session; --forget also removes stored tokens and identity.
    Logout(LogoutArgs),
    /// Raw keychain write for rotation / headless setup.
    SetCredential(SetCredentialArgs),
}

#[derive(Subcommand, Debug)]
enum AccountsCmd {
    /// List investment accounts (account-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum HoldingsCmd {
    /// List positions held in an account, or in every account when none is
    /// selected (holding-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum PositionsCmd {
    /// List positions across accounts (position-list/v1). Spans every account
    /// unless --account names one; the config default account is not used.
    #[command(visible_alias = "ls")]
    List(commands::positions::ListArgs),
}

#[derive(Subcommand, Debug)]
enum DividendsCmd {
    /// List dividend payments, newest first (dividend-list/v1). Spans every
    /// account unless --account names one; the config default is not used.
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum ActivityCmd {
    /// List account activity, newest first (activity-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum LotsCmd {
    /// List tax lots for an account (lot-list/v1).
    #[command(visible_alias = "ls")]
    List(commands::lots::LotsArgs),
}

#[derive(Subcommand, Debug)]
enum TransactionsCmd {
    /// List account transactions, newest first (transaction-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum TransfersCmd {
    /// List money movements, newest first (transfer-list/v1).
    #[command(visible_alias = "ls")]
    List(RangeArgs),
}

#[derive(Subcommand, Debug)]
enum DocumentsCmd {
    /// List statements and tax forms (document-list/v1).
    #[command(visible_alias = "ls")]
    List(commands::documents::ListArgs),
    /// Download a document by id, or every one with --all.
    #[command(visible_alias = "get")]
    Download(commands::documents::DownloadArgs),
}

#[derive(Subcommand, Debug)]
enum ApiCmd {
    /// Send a read-only GraphQL query document.
    ///
    /// Pass `-` to read the document from stdin. `mutation` and
    /// `subscription` operations are refused: this CLI is read-only.
    Query(commands::api::QueryArgs),
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    /// Print the resolved config file path.
    Path,
    /// Show the effective configuration.
    Show,
    /// Set a config key (e.g. `config set account 1234`).
    Set { key: String, value: String },
    /// Remove a config key.
    Unset { key: String },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(&cli) {
        std::process::exit(output::fail(&e, cli.common.json));
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    let store = ConfigStore::new(BIN).with_override(cli.config.clone());
    let creds = CredentialStore::for_binary(BIN);
    let cfg: config::Config = store.load()?;

    let ctx = commands::Ctx {
        common: &cli.common,
        cfg: &cfg,
        creds: &creds,
        account_override: cli.account.as_deref(),
    };

    match &cli.command {
        Command::Auth(cmd) => match cmd {
            AuthCmd::Login(args) => commands::auth::login(&ctx, &store, args),
            AuthCmd::Status => commands::auth::status(&ctx),
            AuthCmd::Logout(args) => commands::auth::logout(&ctx, &store, args),
            AuthCmd::SetCredential(args) => commands::auth::set_credential(&ctx, args),
        },
        Command::Config(cmd) => config_cmd(cli, cmd, &store),
        Command::Accounts(AccountsCmd::List(range)) => commands::accounts::list(&ctx, range),
        Command::Holdings(HoldingsCmd::List(range)) => commands::holdings::list(&ctx, range),
        Command::Positions(PositionsCmd::List(args)) => commands::positions::list(&ctx, args),
        Command::Dividends(DividendsCmd::List(range)) => commands::dividends::list(&ctx, range),
        Command::Activity(ActivityCmd::List(range)) => commands::activity::list(&ctx, range),
        Command::Documents(cmd) => match cmd {
            DocumentsCmd::List(args) => commands::documents::list(&ctx, args),
            DocumentsCmd::Download(args) => commands::documents::download(&ctx, args),
        },
        Command::Lots(LotsCmd::List(args)) => commands::lots::list(&ctx, args),
        Command::Transactions(TransactionsCmd::List(range)) => {
            commands::transactions::list(&ctx, range)
        }
        Command::Transfers(TransfersCmd::List(range)) => commands::transfers::list(&ctx, range),
        Command::NetWorth => commands::networth::show(&ctx),
        Command::Ira => commands::ira::show(&ctx),
        Command::Summary => commands::summary::show(&ctx),
        Command::Status => commands::status::show(&ctx),
        Command::Api(ApiCmd::Query(args)) => commands::api::query(&ctx, args),
        Command::SelfUpdate(args) => Updater {
            repo: REPO.into(),
            binary: BIN.into(),
            target: env!("BUILD_TARGET").into(),
            current: env!("CARGO_PKG_VERSION").into(),
        }
        .run(args, cli.common.json, cli.common.quiet),
        Command::Completions { shell } => {
            clap_complete::generate(*shell, &mut Cli::command(), BIN, &mut std::io::stdout());
            Ok(())
        }
        Command::Info => {
            let info = CliInfo::new(
                BIN,
                env!("CARGO_PKG_VERSION"),
                &format!("https://github.com/{REPO}"),
                AuthInfo {
                    required: true,
                    method: "browser-session".into(),
                    login_hint: Some(auth0::LOGIN.into()),
                },
                &[
                    "accounts",
                    "holdings",
                    "positions",
                    "dividends",
                    "activity",
                    "documents",
                    "lots",
                    "transactions",
                    "transfers",
                    "net-worth",
                    "ira",
                    "summary",
                    "status",
                    "api",
                ],
            )
            .with_profiles(&[pk_cli_documents::PROFILE]);
            output::json(&serde_json::to_value(&info).unwrap());
            Ok(())
        }
    }
}

fn config_cmd(cli: &Cli, cmd: &ConfigCmd, store: &ConfigStore) -> Result<(), CliError> {
    match cmd {
        ConfigCmd::Path => {
            println!("{}", store.path()?.display());
            Ok(())
        }
        ConfigCmd::Show => {
            let cfg: config::Config = store.load()?;
            let v = serde_json::to_value(&cfg).unwrap_or_default();
            if cli.common.json {
                output::json(&v);
            } else {
                output::render(&v);
            }
            Ok(())
        }
        ConfigCmd::Set { key, value } => {
            let mut cfg: config::Config = store.load()?;
            match key.as_str() {
                "username" => cfg.username = Some(value.clone()),
                "account" => cfg.account = Some(value.clone()),
                "base_url" => cfg.base_url = Some(value.clone()),
                "auto_login" => {
                    cfg.auto_login = Some(parse_bool(value)?);
                }
                other => return Err(unknown_key(other)),
            }
            store.save(&cfg)
        }
        ConfigCmd::Unset { key } => {
            let mut cfg: config::Config = store.load()?;
            match key.as_str() {
                "username" => cfg.username = None,
                "account" => cfg.account = None,
                "base_url" => cfg.base_url = None,
                "auto_login" => cfg.auto_login = None,
                other => return Err(unknown_key(other)),
            }
            store.save(&cfg)
        }
    }
}

fn unknown_key(key: &str) -> CliError {
    CliError::Usage(format!(
        "unknown config key `{key}` (known: {})",
        config::Config::KEYS.join(", ")
    ))
}

fn parse_bool(raw: &str) -> Result<bool, CliError> {
    match raw.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Ok(true),
        "false" | "no" | "off" | "0" => Ok(false),
        other => Err(CliError::Usage(format!(
            "expected a boolean (true/false), got `{other}`"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clap_tree_is_valid() {
        // Catches flag collisions (e.g. a subcommand flag shadowing a global
        // like -q) at test time rather than at runtime.
        Cli::command().debug_assert();
    }

    fn login_args(extra: &[&str]) -> Result<commands::auth::LoginCmdArgs, clap::Error> {
        let argv = ["m1f", "auth", "login"].iter().chain(extra);
        match Cli::try_parse_from(argv)?.command {
            Command::Auth(AuthCmd::Login(args)) => Ok(args),
            other => panic!("parsed as {other:?}"),
        }
    }

    /// `--browser` is the browser-session login, alone or beside
    /// `--browser-session`; `--browser-session` alone is the piped route.
    #[test]
    fn browser_implies_the_browser_session() {
        for flags in [&["--browser"][..], &["--browser", "--browser-session"]] {
            let args = login_args(flags).unwrap();
            assert!(
                args.browser.browser && args.is_browser_session(),
                "{flags:?}"
            );
        }
        let piped = login_args(&["--browser-session", "--stdin"]).unwrap();
        assert!(piped.is_browser_session() && !piped.browser.browser);
        assert!(!login_args(&[]).unwrap().is_browser_session());
        // The flags that keep their meaning beside it.
        let kept = login_args(&["--browser", "--overwrite", "--no-verify"]).unwrap();
        assert!(kept.base.overwrite && kept.base.no_verify);
    }

    /// The browser is the session's only source: a second source, or the
    /// password login's flags, is refused at parse time (exit 2).
    #[test]
    fn browser_refuses_other_sources_and_the_password_flags() {
        for extra in [
            &["--stdin"][..],
            &["--from-env", "M1F_SESSION"],
            &["--username", "owner@example.invalid"],
            &["--code", "000000"],
        ] {
            let flags: Vec<&str> = ["--browser"].iter().chain(extra).copied().collect();
            let err = login_args(&flags).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{flags:?}"
            );
            assert_eq!(err.exit_code(), 2, "{flags:?}");
        }
    }

    #[test]
    fn booleans_accept_the_usual_spellings() {
        assert!(parse_bool("true").unwrap());
        assert!(parse_bool("YES").unwrap());
        assert!(!parse_bool("off").unwrap());
        assert_eq!(parse_bool("maybe").unwrap_err().exit_code(), 2);
    }

    #[test]
    fn unknown_config_key_lists_the_known_ones() {
        let e = unknown_key("nope");
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains("username"), "{e}");
        assert!(e.to_string().contains("auto_login"), "{e}");
    }
}
