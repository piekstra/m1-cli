//! `m1f mcp`: M1 net worth, positions, activity, tax documents, realized gains
//! and queued trading as MCP tools (cli-common DESIGN.md §1.9, the MCP profile),
//! for Claude Code, Claude Desktop and any MCP client.
//!
//! Five read-only tools over the same GraphQL reads and mappers the commands
//! use: `m1_portfolio` (net worth, every account's total, positions),
//! `m1_activity` (trades, dividends and transfers over a date range),
//! `m1_documents` (statements and tax forms, listed, never downloaded),
//! `m1_realized_gains` (closed lots and their gains by sale date) and
//! `m1_trading` (queued orders, auto-invest, the next trade window, pending
//! transfers). Nothing here can write: a tool sends only the fixed query
//! documents its command does, and takes no document from its caller.
//!
//! Provider access goes through [`Source`], the per-target seam of
//! cli-common's MCP profile (DESIGN.md §2.3); the tests run every tool
//! offline against the fixtures through it. [`LiveSource`] signs in with the
//! session `m1f auth login --browser` stored in the keychain, and only when
//! a tool is called: listing the tools touches no credential. It never
//! signs in itself: a missing or dead session is an auth error naming that
//! command.

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use pk_cli_core::{dates, CliError, CommonArgs, Money, RangeArgs};
use pk_cli_documents::Document;
use pk_cli_mcp::{
    hold_within, parse_args, ListArgs, Order, Page, PageRequest, PositionKey, PositionRequest,
    Server, ToolDef, ToolError, ToolOutput, Toolset,
};
use pk_cli_secrets::CredentialStore;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::commands::accounts::{self, AccountRef};
use crate::commands::{activity, documents, holdings, lots, networth, positions, trading, Ctx};
use crate::config::Config;
use crate::parse;

pub const PORTFOLIO_TOOL: &str = "m1_portfolio";
pub const ACTIVITY_TOOL: &str = "m1_activity";
pub const DOCUMENTS_TOOL: &str = "m1_documents";
pub const GAINS_TOOL: &str = "m1_realized_gains";
pub const TRADING_TOOL: &str = "m1_trading";

/// How long a call waits for the one before it. Parallel calls from one model turn are normal and
/// short; past this, the model is better told than left to retry into a queue.
const QUEUE_WAIT: Duration = Duration::from_secs(45);

/// What a sign-in failure asks of the user. M1's password login is closed
/// (an HTTP 403 since 2026-10-27), so the standard `m1f auth login` remedy
/// would send them to a dead end.
const SIGN_IN: &str = "Ask the user to run `m1f auth login --browser --overwrite` in a terminal, \
                       then call the tool again. Tools never sign in or create credentials \
                       themselves";

/// The fix for an answer shaped like a block at the edge, where a new sign-in comes last
/// ([`crate::client::edge_block_advice`]).
const AFTER_A_BLOCK: &str = "Wait or try another network, then call the tool again once. Only if \
                             it still fails after that, ask the user to run `m1f auth login \
                             --browser --overwrite` in a terminal. Tools never sign in or create \
                             credentials themselves";

/// Where the tools get M1's data: the live GraphQL API, or fixtures.
#[allow(async_fn_in_trait)] // deliberate: no `Send` bound, as in `Toolset`
pub trait Source {
    /// One tool call's turn, held for the whole call: a call reads once per account, and the
    /// wait in the queue has to be spent once to leave room to answer inside the call's limit.
    fn turn(&self) -> Result<Option<MutexGuard<'_, ()>>, CliError> {
        Ok(None)
    }
    /// Every account node on the login (`viewer.accounts`).
    async fn accounts(&self) -> Result<Vec<Value>, CliError>;
    /// M1's net-worth rollup (`viewer.overview.balances`).
    async fn balances(&self) -> Result<Value, CliError>;
    /// One account's holding nodes.
    async fn holdings(&self, account_id: &str) -> Result<Vec<Value>, CliError>;
    /// One account's activity rows (`activity::activity_dto`), newest first,
    /// back past `since`; and whether the page ceiling stopped the walk.
    async fn activity(&self, account_id: &str, since: &str)
        -> Result<(Vec<Value>, bool), CliError>;
    /// Documents of `types` dated in the window, newest first.
    async fn documents(
        &self,
        types: &[&str],
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Vec<Document>, CliError>;
    /// One account's closed lots (`lots::lot_dto`); and whether the page
    /// ceiling stopped the walk.
    async fn closed_lots(&self, account_id: &str) -> Result<(Vec<Value>, bool), CliError>;
    /// One account's trading node (`trading::account_dto` maps it).
    async fn trading(&self, account_id: &str) -> Result<Value, CliError>;
}

/// The live API, through the same [`Ctx`] the commands use.
pub struct LiveSource {
    common: CommonArgs,
    cfg: Config,
    creds: CredentialStore,
    one_at_a_time: Mutex<()>,
}

impl LiveSource {
    pub fn new(common: &CommonArgs, cfg: Config, creds: CredentialStore) -> Self {
        Self {
            // Quiet: stdout is the protocol, and the commands' stderr notes
            // ("access token expired — refreshing") are for a person.
            common: CommonArgs {
                json: true,
                quiet: true,
                ..common.clone()
            },
            cfg,
            creds,
            one_at_a_time: Mutex::new(()),
        }
    }

    /// Run `f` with a context. A lapsed access token is refreshed inside `Ctx::read`, under a
    /// lock that also holds off every other `m1f` process, because the refresh rotates the stored
    /// refresh token and Auth0 can revoke the whole session when one is reused.
    fn with_ctx<T>(&self, f: impl FnOnce(&Ctx) -> Result<T, CliError>) -> Result<T, CliError> {
        f(&Ctx {
            common: &self.common,
            cfg: &self.cfg,
            creds: &self.creds,
            account_override: None,
        })
    }
}

/// A call's turn at M1, or the error that says another call still has it.
fn turn_within(lock: &Mutex<()>, wait: Duration) -> Result<MutexGuard<'_, ()>, CliError> {
    hold_within(lock, wait).ok_or_else(|| {
        CliError::Upstream(
            "another call to M1 is still running in this server, and may be waiting on a keychain \
             prompt on this computer; ask the user to check for one, then try again"
                .into(),
        )
    })
}

/// Blocking inside `async fn` is deliberate: the stdio server polls each call
/// on its own blocking thread with no Tokio reactor (pk-cli-mcp's `Toolset`
/// contract), which is where `reqwest::blocking` belongs.
impl Source for LiveSource {
    fn turn(&self) -> Result<Option<MutexGuard<'_, ()>>, CliError> {
        turn_within(&self.one_at_a_time, QUEUE_WAIT).map(Some)
    }

    async fn accounts(&self) -> Result<Vec<Value>, CliError> {
        self.with_ctx(accounts::fetch_nodes)
    }

    async fn balances(&self) -> Result<Value, CliError> {
        self.with_ctx(networth::fetch_balances)
    }

    async fn holdings(&self, account_id: &str) -> Result<Vec<Value>, CliError> {
        self.with_ctx(|ctx| holdings::fetch_nodes(ctx, account_id))
    }

    async fn activity(
        &self,
        account_id: &str,
        since: &str,
    ) -> Result<(Vec<Value>, bool), CliError> {
        let range = RangeArgs {
            since: Some(since.to_string()),
            ..RangeArgs::default()
        };
        self.with_ctx(|ctx| activity::fetch(ctx, account_id, &range))
    }

    async fn documents(
        &self,
        types: &[&str],
        since: Option<&str>,
        until: Option<&str>,
    ) -> Result<Vec<Document>, CliError> {
        let range = RangeArgs {
            since: since.map(String::from),
            until: until.map(String::from),
            limit: None,
        };
        // Only the document leaves, and never a raw id: the raw id and the
        // signed URL beside it are credentials (documents.rs).
        self.with_ctx(|ctx| documents::fetch(ctx, &range, types))
            .map(|fetched| {
                fetched
                    .into_iter()
                    .map(documents::Fetched::listed)
                    .collect()
            })
    }

    async fn closed_lots(&self, account_id: &str) -> Result<(Vec<Value>, bool), CliError> {
        self.with_ctx(|ctx| lots::fetch(ctx, account_id, &["CLOSED"], &RangeArgs::default()))
    }

    async fn trading(&self, account_id: &str) -> Result<Value, CliError> {
        self.with_ctx(|ctx| trading::fetch_node(ctx, account_id))
    }
}

/// The toolset `m1f mcp` serves.
pub struct M1Tools<S: Source> {
    source: S,
}

impl<S: Source> M1Tools<S> {
    pub fn new(source: S) -> Self {
        Self { source }
    }

    #[cfg(test)]
    pub fn source(&self) -> &S {
        &self.source
    }
}

/// A provider failure as a tool error; a sign-in failure names the browser
/// login.
fn tool_err(e: CliError) -> ToolError {
    match e {
        CliError::Upstream(m) if m.contains(crate::client::SIGN_IN_MAY_NOT_HELP) => {
            ToolError::upstream(m).with_fix(AFTER_A_BLOCK)
        }
        CliError::Auth(m) => ToolError::auth(m).with_fix(SIGN_IN),
        other => other.into(),
    }
}

// ---- m1_portfolio -----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PortfolioArgs {
    /// Only this account (name or id).
    #[serde(default)]
    pub account: Option<String>,
    /// Only this symbol.
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct PortfolioFilter<'a> {
    account: Option<&'a str>,
    symbol: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct NetWorth {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assets: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub liabilities: Option<String>,
    /// M1 marks its own total incomplete.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub partial: bool,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct AccountTotal {
    pub name: String,
    /// individual, joint, ira_roth, ira_traditional, ... or M1's product
    /// (Earn, Borrow, Spend).
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// Absent where M1 cannot price the account.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct PositionItem {
    pub symbol: String,
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_basis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unrealized_gain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cusip: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct PortfolioOut {
    pub net_worth: NetWorth,
    pub accounts: Vec<AccountTotal>,
    #[serde(flatten)]
    pub page: Page<PositionItem>,
}

// ---- m1_activity ------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActivityArgs {
    /// First day, YYYY-MM-DD. Default: Jan 1 of until's year.
    #[serde(default)]
    pub since: Option<String>,
    /// Last day, YYYY-MM-DD. Default: today.
    #[serde(default)]
    pub until: Option<String>,
    /// Only this account (name or id).
    #[serde(default)]
    pub account: Option<String>,
    /// Trade, Cash (deposits, withdrawals, dividends) or Position.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// Only this symbol.
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct ActivityFilter<'a> {
    since: &'a str,
    until: &'a str,
    account: Option<&'a str>,
    kind: Option<&'a str>,
    symbol: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct ActivityItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Signed cash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_price: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct ActivityOut {
    pub since: String,
    pub until: String,
    /// False when an account had more history than one call reads: narrow
    /// since/until.
    pub complete: bool,
    #[serde(flatten)]
    pub page: Page<ActivityItem>,
}

// ---- m1_documents -----------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DocumentsArgs {
    /// tax-form, statement, trade-confirmation, investments-related or
    /// account-document.
    #[serde(default, rename = "type")]
    pub kind: Option<String>,
    /// Dated on or after, YYYY-MM-DD.
    #[serde(default)]
    pub since: Option<String>,
    /// Dated on or before, YYYY-MM-DD.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct DocumentsFilter<'a> {
    types: &'a [&'a str],
    since: Option<&'a str>,
    until: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct DocumentItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    pub name: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// For `m1f documents download <id>`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct DocumentsOut {
    #[serde(flatten)]
    pub page: Page<DocumentItem>,
}

// ---- m1_realized_gains ------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GainsArgs {
    /// First sale day, YYYY-MM-DD. Default: Jan 1 of until's year.
    #[serde(default)]
    pub since: Option<String>,
    /// Last sale day, YYYY-MM-DD. Default: today.
    #[serde(default)]
    pub until: Option<String>,
    /// One account (name or id), IRAs included. Default: every taxable
    /// account.
    #[serde(default)]
    pub account: Option<String>,
    /// Only this symbol.
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(flatten)]
    pub list: ListArgs,
}

#[derive(Serialize)]
struct GainsFilter<'a> {
    since: &'a str,
    until: &'a str,
    account: Option<&'a str>,
    symbol: Option<&'a str>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct GainTotals {
    pub short_term: String,
    pub long_term: String,
    pub total: String,
    pub disallowed_wash_sale: String,
    pub lots: usize,
    /// Closed lots with no sale date: in no figure, as no year holds them.
    #[serde(skip_serializing_if = "is_zero")]
    pub undated: usize,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub struct LotItem {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sold: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquired: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_basis: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gain: Option<String>,
    /// Short or Long.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub term: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disallowed_wash_sale: Option<String>,
    pub account: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cusip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct GainsOut {
    pub since: String,
    pub until: String,
    /// Over every matching lot, not just this page.
    pub totals: GainTotals,
    /// False when an account had more lots than one call reads.
    pub complete: bool,
    #[serde(flatten)]
    pub page: Page<LotItem>,
}

// ---- m1_trading -------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TradingArgs {
    /// Only this account (name or id).
    #[serde(default)]
    pub account: Option<String>,
}

/// Each account is `m1f trading --json`'s entry with its amounts as decimal
/// strings. Its fields go undeclared here because declaring them would not fit
/// the 8,000 characters the definitions share; the description names them, and
/// `the_trading_tool_returns_the_commands_data` holds them to the command's.
/// One entry per account, as with `m1_portfolio`'s `accounts`, so it takes no
/// `limit` or `cursor`: `account` narrows a result that is too large.
#[derive(Debug, Serialize, JsonSchema)]
pub struct TradingOut {
    pub accounts: Vec<serde_json::Map<String, Value>>,
}

// ---- the toolset ------------------------------------------------------------

/// What `ListArgs` says of its arguments, shortened. Four tools repeat it, and it
/// is the only text long enough to make room for a fifth tool inside the 8,000
/// characters all the definitions share.
const LIST_ARGS: [(&str, &str); 3] = [
    ("limit", "1 to 200 (default 25)."),
    ("cursor", "The previous page's `next_cursor`."),
    (
        "response_format",
        "`detailed` adds ids and provider detail.",
    ),
];

fn short_list_args(mut tool: ToolDef) -> ToolDef {
    for (arg, description) in LIST_ARGS {
        if let Some(schema) = tool.input_schema["properties"].get_mut(arg) {
            schema["description"] = Value::from(description);
        }
    }
    tool
}

impl<S: Source> Toolset for M1Tools<S> {
    fn server(&self) -> Server {
        Server::new("m1f", env!("CARGO_PKG_VERSION"), "M1", "m1").instructions(
            "M1 access here is read-only: no tool can trade, transfer or change anything. M1 \
             sign-in is through a browser: the command to ask for is `m1f auth login \
             --browser`, with `--overwrite` if a session is already stored. Amounts are USD \
             decimal strings; keep every digit when adding them.",
        )
    }

    fn tools(&self) -> Vec<ToolDef> {
        let tools = vec![
            ToolDef::read(
                PORTFOLIO_TOOL,
                "M1 portfolio",
                "Shows the user's M1 net worth, account totals and positions. Use it for what \
                 they own at M1. Returns net_worth, accounts and position items. Narrow with \
                 account or symbol.",
            )
            .input::<PortfolioArgs>()
            .output::<PortfolioOut>(),
            ToolDef::read(
                ACTIVITY_TOOL,
                "M1 activity",
                "Lists M1 activity in a date range, newest first: trades, deposits, \
                 withdrawals, dividends. Use it for what happened in a period. Items carry \
                 date, type, description, symbol, amount and account. Defaults to the year to \
                 date; narrow with account, type or symbol.",
            )
            .input::<ActivityArgs>()
            .output::<ActivityOut>(),
            ToolDef::read(
                DOCUMENTS_TOOL,
                "M1 documents",
                "Lists M1 statements and tax forms, newest first, without \
                 downloading them. Use it to see which 1099s or statements exist. Items carry \
                 date, name and type. Narrow with type (tax-form) or since/until.",
            )
            .input::<DocumentsArgs>()
            .output::<DocumentsOut>(),
            ToolDef::read(
                GAINS_TOOL,
                "M1 realized gains",
                "Lists M1 tax lots sold in a date range, with exact totals by holding term. \
                 Use it for a year's realized gains, losses and wash sales. Returns totals and \
                 lot items. Defaults to the year to date in taxable accounts; narrow with \
                 account or symbol.",
            )
            .input::<GainsArgs>()
            .output::<GainsOut>(),
            ToolDef::read(
                TRADING_TOOL,
                "M1 trading",
                "Shows what is queued in each M1 account and when it trades. Use it for whether a \
                 sale is queued and what cash or transfer waits. Returns accounts with status, \
                 auto_invest, trading, orders, estimated, cash, total_value and \
                 pending_transfers; null means no figure. Narrow with account.",
            )
            .input::<TradingArgs>()
            .output::<TradingOut>(),
        ];
        tools.into_iter().map(short_list_args).collect()
    }

    async fn call(&self, name: &str, args: Value) -> Result<ToolOutput, ToolError> {
        match name {
            PORTFOLIO_TOOL => self.portfolio(parse_args(args)?).await,
            ACTIVITY_TOOL => self.activity(parse_args(args)?).await,
            DOCUMENTS_TOOL => self.documents(parse_args(args)?).await,
            GAINS_TOOL => self.gains(parse_args(args)?).await,
            TRADING_TOOL => self.trading(parse_args(args)?).await,
            other => Err(ToolError::other(format!("no handler for {other}"))),
        }
    }
}

impl<S: Source> M1Tools<S> {
    async fn portfolio(&self, args: PortfolioArgs) -> Result<ToolOutput, ToolError> {
        let account = non_empty(args.account.as_deref());
        let symbol = non_empty(args.symbol.as_deref());
        let page = PageRequest::new(&args.list, &PortfolioFilter { account, symbol })?;
        let detailed = args.list.format().is_detailed();

        let _turn = self.source.turn().map_err(tool_err)?;
        let nodes = self.source.accounts().await.map_err(tool_err)?;
        let all = account_refs(&nodes)?;
        let scope = pick(&all, account)?;
        let balances = self.source.balances().await.map_err(tool_err)?;
        let built = networth::networth_dto(&balances, &nodes).map_err(tool_err)?;

        let mut matched = Vec::new();
        for acct in scope {
            for node in self.source.holdings(&acct.id).await.map_err(tool_err)? {
                let row = positions::position_row(&node).map_err(tool_err)?;
                if symbol.is_some_and(|s| {
                    !text(&row, "symbol").is_some_and(|x| x.eq_ignore_ascii_case(s))
                }) {
                    continue;
                }
                matched.push(position_item(&row, acct, detailed));
            }
        }
        ToolOutput::new(&PortfolioOut {
            net_worth: net_worth(&built.dto),
            accounts: account_totals(&built.dto, detailed),
            page: page.page(matched, "account or symbol")?,
        })
    }

    async fn activity(&self, args: ActivityArgs) -> Result<ToolOutput, ToolError> {
        let (since, until) = window(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let account = non_empty(args.account.as_deref());
        let kind = non_empty(args.kind.as_deref());
        let symbol = non_empty(args.symbol.as_deref());
        let page = PositionRequest::new(
            &args.list,
            &ActivityFilter {
                since: &since,
                until: &until,
                account,
                kind,
                symbol,
            },
        )?;
        let detailed = args.list.format().is_detailed();

        let _turn = self.source.turn().map_err(tool_err)?;
        let nodes = self.source.accounts().await.map_err(tool_err)?;
        let all = account_refs(&nodes)?;
        let mut complete = true;
        let mut matched: Vec<(PositionKey, ActivityItem)> = Vec::new();
        for acct in pick(&all, account)? {
            let (rows, capped) = self
                .source
                .activity(&acct.id, &since)
                .await
                .map_err(tool_err)?;
            complete &= !capped;
            for row in rows {
                let date = text(&row, "date");
                if date
                    .as_deref()
                    .is_some_and(|d| d < since.as_str() || d > until.as_str())
                    || !matches_text(&row, "type", kind)
                    || !matches_text(&row, "symbol", symbol)
                {
                    continue;
                }
                let item = ActivityItem {
                    date: date.clone(),
                    kind: text(&row, "type"),
                    description: text(&row, "description"),
                    symbol: text(&row, "symbol"),
                    amount: amount(&row, "amount"),
                    account: label(acct),
                    share_price: amount(&row, "share_price").filter(|_| detailed),
                    id: text(&row, "id").filter(|_| detailed),
                };
                let key = row_key(date.as_deref().unwrap_or_default(), acct, &row);
                matched.push((key, item));
            }
        }
        ToolOutput::new(&ActivityOut {
            since,
            until,
            complete,
            page: page.page(
                matched,
                Order::Descending,
                "since/until, account, type or symbol",
            )?,
        })
    }

    async fn documents(&self, args: DocumentsArgs) -> Result<ToolOutput, ToolError> {
        let types = documents::type_filter(non_empty(args.kind.as_deref()))
            .map_err(|e| ToolError::usage(e.to_string()))?;
        let since = date_arg("since", non_empty(args.since.as_deref()))?;
        let until = date_arg("until", non_empty(args.until.as_deref()))?;
        if let (Some(s), Some(u)) = (&since, &until) {
            if s > u {
                return Err(ToolError::usage(format!(
                    "since ({s}) is after until ({u})"
                )));
            }
        }
        let page = PositionRequest::new(
            &args.list,
            &DocumentsFilter {
                types: &types,
                since: since.as_deref(),
                until: until.as_deref(),
            },
        )?;
        let detailed = args.list.format().is_detailed();
        let _turn = self.source.turn().map_err(tool_err)?;
        let docs = self
            .source
            .documents(&types, since.as_deref(), until.as_deref())
            .await
            .map_err(tool_err)?;
        let matched = docs
            .into_iter()
            .map(|d| {
                let key = PositionKey::new(d.date.as_deref().unwrap_or_default(), &d.id);
                let item = DocumentItem {
                    date: d.date,
                    name: d.name,
                    kind: d.category.map(|c| c.to_ascii_lowercase().replace('_', "-")),
                    id: Some(d.id).filter(|id| detailed && !id.is_empty()),
                };
                (key, item)
            })
            .collect();
        ToolOutput::new(&DocumentsOut {
            page: page.page(matched, Order::Descending, "type or since/until")?,
        })
    }

    async fn gains(&self, args: GainsArgs) -> Result<ToolOutput, ToolError> {
        let (since, until) = window(
            non_empty(args.since.as_deref()),
            non_empty(args.until.as_deref()),
        )?;
        let account = non_empty(args.account.as_deref());
        let symbol = non_empty(args.symbol.as_deref());
        let page = PositionRequest::new(
            &args.list,
            &GainsFilter {
                since: &since,
                until: &until,
                account,
                symbol,
            },
        )?;
        let detailed = args.list.format().is_detailed();

        let _turn = self.source.turn().map_err(tool_err)?;
        let nodes = self.source.accounts().await.map_err(tool_err)?;
        let all = account_refs(&nodes)?;
        // A sale inside an IRA is not a taxable event; those lots come only
        // when the call names the account.
        let scope: Vec<&AccountRef> = match account {
            Some(_) => pick(&all, account)?,
            None => all.iter().filter(|a| !a.is_retirement).collect(),
        };
        let range = RangeArgs {
            since: Some(since.clone()),
            until: Some(until.clone()),
            limit: None,
        };
        let mut complete = true;
        let mut sums = Sums::default();
        let mut matched: Vec<(PositionKey, LotItem)> = Vec::new();
        for acct in scope {
            let (rows, capped) = self.source.closed_lots(&acct.id).await.map_err(tool_err)?;
            complete &= !capped;
            for row in rows {
                if !matches_text(&row, "symbol", symbol) {
                    continue;
                }
                // A gain belongs to the year of its sale. `lots list` keeps a
                // lot with no sale date (or windows it by its acquisition);
                // a total cannot, so such a lot is counted apart.
                let Some(sold) = text(&row, "closed") else {
                    sums.undated += 1;
                    continue;
                };
                if !lots::in_lots_window(&row, &range) {
                    continue;
                }
                sums.add(&row)?;
                let item = LotItem {
                    symbol: text(&row, "symbol"),
                    sold: Some(sold.clone()),
                    acquired: text(&row, "acquired"),
                    quantity: text(&row, "quantity"),
                    cost_basis: amount(&row, "cost_basis"),
                    gain: amount(&row, "realized_gain"),
                    term: text(&row, "term"),
                    disallowed_wash_sale: amount(&row, "disallowed_wash_sale")
                        .filter(|a| detailed || parse::cents(a).is_some_and(|c| c != 0)),
                    account: label(acct),
                    cusip: text(&row, "cusip").filter(|_| detailed),
                    id: text(&row, "id").filter(|_| detailed),
                };
                matched.push((row_key(&sold, acct, &row), item));
            }
        }
        ToolOutput::new(&GainsOut {
            since,
            until,
            totals: sums.totals(),
            complete,
            page: page.page(matched, Order::Descending, "since/until, account or symbol")?,
        })
    }

    async fn trading(&self, args: TradingArgs) -> Result<ToolOutput, ToolError> {
        let account = non_empty(args.account.as_deref());

        let _turn = self.source.turn().map_err(tool_err)?;
        let nodes = self.source.accounts().await.map_err(tool_err)?;
        let all = account_refs(&nodes)?;
        let mut accounts = Vec::new();
        for acct in pick(&all, account)? {
            let node = self.source.trading(&acct.id).await.map_err(tool_err)?;
            let dto = trading::account_dto(&node).map_err(tool_err)?;
            if let Value::Object(fields) = plain_amounts(dto) {
                accounts.push(fields);
            }
        }
        ToolOutput::new(&TradingOut { accounts })
    }
}

/// Where a row belongs in a newest-first list across accounts: its date, then its account and id.
fn row_key(date: &str, acct: &AccountRef, row: &Value) -> PositionKey {
    let id = text(row, "id").unwrap_or_default();
    PositionKey::new(date, &format!("{}:{id}", acct.id))
}

/// Exact sums in cents: a float would drift on a year of lots.
#[derive(Default)]
struct Sums {
    short: i64,
    long: i64,
    total: i64,
    wash: i64,
    lots: usize,
    undated: usize,
}

impl Sums {
    fn add(&mut self, row: &Value) -> Result<(), ToolError> {
        let cents = |key: &str| -> Result<i64, ToolError> {
            match amount(row, key) {
                None => Ok(0),
                Some(a) => parse::cents(&a).ok_or_else(|| {
                    ToolError::upstream(format!("lot `{key}` `{a}` is not a decimal amount"))
                }),
            }
        };
        self.short += cents("realized_gain_short")?;
        self.long += cents("realized_gain_long")?;
        self.total += cents("realized_gain")?;
        self.wash += cents("disallowed_wash_sale")?;
        self.lots += 1;
        Ok(())
    }

    fn totals(&self) -> GainTotals {
        let s = |c: i64| Money::from_cents(c).amount;
        GainTotals {
            short_term: s(self.short),
            long_term: s(self.long),
            total: s(self.total),
            disallowed_wash_sale: s(self.wash),
            lots: self.lots,
            undated: self.undated,
        }
    }
}

fn account_refs(nodes: &[Value]) -> Result<Vec<AccountRef>, ToolError> {
    nodes
        .iter()
        .map(AccountRef::from_node)
        .collect::<Result<_, _>>()
        .map_err(tool_err)
}

/// The accounts `wanted` names (by id, or by name ignoring case), or every
/// account when it names none. An unknown name is not found, listing the
/// names that exist.
fn pick<'a>(all: &'a [AccountRef], wanted: Option<&str>) -> Result<Vec<&'a AccountRef>, ToolError> {
    let Some(wanted) = wanted else {
        return Ok(all.iter().collect());
    };
    let hit: Vec<&AccountRef> = all
        .iter()
        .filter(|a| a.id == wanted || label(a).eq_ignore_ascii_case(wanted))
        .collect();
    if hit.is_empty() {
        let names: Vec<String> = all.iter().map(label).collect();
        return Err(ToolError::not_found(format!(
            "no M1 account named `{wanted}`; the accounts are: {}",
            names.join(", ")
        ))
        .with_fix("Call again with one of those names"));
    }
    Ok(hit)
}

/// An account's name for a person: its nickname or product name, else its
/// type, else its id.
fn label(a: &AccountRef) -> String {
    a.name
        .clone()
        .or_else(|| a.account_type().map(String::from))
        .unwrap_or_else(|| a.id.clone())
}

fn position_item(row: &Value, acct: &AccountRef, detailed: bool) -> PositionItem {
    let detail = |v: Option<String>| v.filter(|_| detailed);
    PositionItem {
        symbol: text(row, "symbol").unwrap_or_default(),
        account: label(acct),
        quantity: text(row, "quantity"),
        market_value: amount(row, "market_value"),
        cost_basis: amount(row, "cost_basis"),
        unrealized_gain: amount(row, "unrealized_gain"),
        name: detail(text(row, "name")),
        average_price: detail(amount(row, "average_price")),
        cusip: detail(text(row, "cusip")),
    }
}

fn net_worth(dto: &Value) -> NetWorth {
    NetWorth {
        total: amount(dto, "total"),
        assets: amount(dto, "assets"),
        liabilities: amount(dto, "liabilities"),
        partial: dto.get("is_partial") == Some(&Value::Bool(true)),
    }
}

fn account_totals(dto: &Value, detailed: bool) -> Vec<AccountTotal> {
    let rows = dto
        .get("accounts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    rows.iter()
        .map(|r| {
            let kind = text(r, "type");
            AccountTotal {
                name: text(r, "name").or_else(|| kind.clone()).unwrap_or_default(),
                kind,
                total: amount(r, "total"),
                account_id: text(r, "account_id").filter(|_| detailed),
            }
        })
        .collect()
}

/// A string field, or a number as M1 sent it.
fn text(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// A `Money` field's decimal amount (`{"amount": "1.00", ...}`).
fn amount(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|m| m.get("amount"))
        .and_then(Value::as_str)
        .map(String::from)
}

/// Every `Money` in a DTO as its decimal string, as every tool returns amounts.
fn plain_amounts(v: Value) -> Value {
    match v {
        Value::Object(fields) => match fields.get("amount").and_then(Value::as_str) {
            Some(amount) if fields.len() == 2 && fields.contains_key("currency") => {
                Value::String(amount.to_string())
            }
            _ => Value::Object(
                fields
                    .into_iter()
                    .map(|(k, field)| (k, plain_amounts(field)))
                    .collect(),
            ),
        },
        Value::Array(rows) => Value::Array(rows.into_iter().map(plain_amounts).collect()),
        other => other,
    }
}

fn matches_text(row: &Value, key: &str, wanted: Option<&str>) -> bool {
    wanted.is_none_or(|w| text(row, key).is_some_and(|x| x.eq_ignore_ascii_case(w)))
}

fn non_empty(s: Option<&str>) -> Option<&str> {
    s.map(str::trim).filter(|s| !s.is_empty())
}

/// A date argument, zero-padded (`2026-1-5` is `2026-01-05`) so the string
/// comparisons that filter rows are date comparisons.
fn date_arg(name: &str, v: Option<&str>) -> Result<Option<String>, ToolError> {
    v.map(|d| {
        dates::parse_iso(d).map(dates::fmt_iso).map_err(|_| {
            ToolError::usage(format!("{name} must be a date as YYYY-MM-DD, got `{d}`"))
        })
    })
    .transpose()
}

/// The inclusive window, defaulting to the year to date.
fn window(since: Option<&str>, until: Option<&str>) -> Result<(String, String), ToolError> {
    let since = date_arg("since", since)?;
    let until = date_arg("until", until)?.unwrap_or_else(|| dates::fmt_iso(dates::today()));
    let since = since.unwrap_or_else(|| format!("{}-01-01", &until[..4]));
    if since > until {
        return Err(ToolError::usage(format!(
            "since ({since}) is after until ({until})"
        )));
    }
    Ok((since, until))
}

#[cfg(test)]
mod tests;
