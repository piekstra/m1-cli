//! GraphQL document handling: the read-only guard for the `api query`
//! passthrough, plus the operation documents this CLI sends.
//!
//! The guard exists because `m1f` is a read-only tool over someone's real
//! brokerage account. The passthrough hands a user-supplied document straight
//! to M1's backend, so it is the one place an arbitrary `mutation` could slip
//! in — closing trades, moving money, changing settings. We refuse anything
//! that isn't a query.
//!
//! The parsing is deliberately structural rather than a regex over the raw
//! text. `mutation` appears legitimately as a *field* name, inside strings, and
//! inside comments; a naive `contains("mutation")` would reject valid reads,
//! and a naive `starts_with` would miss a mutation that follows a fragment
//! definition. So we blank out comments and string literals, then look only at
//! words sitting at brace/paren/bracket depth zero — where operation keywords
//! live and field names cannot.

use pk_cli_core::CliError;

// ---------------------------------------------------------------------------
// Operation documents
// ---------------------------------------------------------------------------
//
// Every selection below is **schema-verified**: `lens.m1.com` answers
// introspection queries without authentication, and the full schema was pulled
// on 2026-08-13. Field names, argument names, scalar types, and enum members
// come from that dump, not from guesswork. What introspection cannot show —
// the runtime *values* (date formats, whether a Float arrives with cents,
// Cloudflare's behavior under sustained authenticated use) — is tracked in
// docs/api.md.
//
// If a field selection drifts (M1 redeploys), the server answers HTTP 200 with
// a top-level `errors[]` naming the field; `client::classify_errors` surfaces
// it loudly rather than as a silent empty result.
//
// NOTE ON PAGINATION: it differs per connection, so there is deliberately no
// single generic paginator in this crate. Every connection here carries
// `pageInfo`, but page-size limits and cursor semantics are per-connection;
// each command owns its loop with a page cap.

/// Password login. Also the MFA step: re-send the SAME mutation with
/// `emailCode` populated.
///
/// **Blocked at the edge since 2026-10-27**: Cloudflare answers it with an
/// HTTP 403 HTML page (docs/api.md, "Trap 7") and M1's web app now signs in
/// through Auth0 (`crate::auth0`). Kept for the day the edge lets it through
/// again; `auth login` names the trap when it does not.
///
/// `outcome` is a plain object (`AuthenticateOutcome`), **not** a union — there
/// is no separate challenge type and no separate resume mutation. When MFA is
/// required M1 signals it through `error`, an `AuthenticateErrorEnum` whose
/// members include `CODE_REQUIRED` and `EMAIL_AMFA_REQUIRED`, and expects the
/// whole login to be replayed with the code added (`AuthenticateInput.emailCode`
/// — schema-verified). `expiresIn` is seconds until the access token lapses.
pub const AUTHENTICATE: &str = r#"mutation Authenticate($input: AuthenticateInput!) {
  authenticate(input: $input) {
    didSucceed
    error
    expiresIn
    outcome {
      accessToken
      refreshToken
    }
  }
}"#;

/// Exchange a refresh token for a fresh pair.
///
/// Tokens **rotate**: the response carries a new refresh token that must be
/// persisted, or the next refresh fails against a token M1 has already retired.
/// `error` is a `ReauthenticateErrorEnum`: `INVALID_REFRESH_TOKEN` or
/// `USER_ACCOUNT_LOCKED`.
pub const REAUTHENTICATE: &str = r#"mutation Reauthenticate($input: ReauthenticateInput!) {
  reauthenticate(input: $input) {
    didSucceed
    error
    outcome {
      accessToken
      refreshToken
    }
  }
}"#;

/// Unauthenticated liveness probe — distinguishes "M1 is down" or "Cloudflare
/// is challenging us" from "your session died", without spending a credential.
///
/// The bundle-decoded guess was a root `checkSystemStatus` field; the live
/// schema rejects that. The real probe is `Query.system: SystemInfo!`, whose
/// `status` is a `SystemStatusEnum`: NORMAL / DEGRADED / DISRUPTED /
/// MAINTENANCE.
pub const SYSTEM_STATUS: &str = r#"query SystemStatus {
  system {
    status
    statusMessage
    isStatusBlocking
    version
  }
}"#;

/// Whether the bearer token is accepted — the browser-session login's one
/// verification read. Observed 2026-10-27: `Viewer.isAuthenticated` answers
/// `false` with no error both without a token and with a bogus one, so the
/// check is the flag, not the envelope. It reads no account data.
pub const VIEWER_IS_AUTHENTICATED: &str = r#"query ViewerIsAuthenticated {
  viewer {
    isAuthenticated
  }
}"#;

/// Household net worth, cross-account (schema- and live-verified 2026-08-18).
///
/// `viewer.overview.balances` (`BalancesOverview`) is M1's own home-screen
/// rollup: `total` net worth, `assets`/`liabilities` as `NetWorthLabel
/// { label value }`, `assetRatio`, and `accountTotals` — a `[{ type, total }]`
/// breakdown by product line (Invest / Earn / Borrow / Spend). `isPartialTotal`
/// is M1's own flag that a figure is incomplete (a value it couldn't price),
/// surfaced so a machine consumer doesn't trust a partial total as final.
pub const NET_WORTH: &str = r#"query NetWorthOverview {
  viewer {
    overview {
      balances {
        total
        assetRatio
        isPartialTotal
        assets {
          label
          value
        }
        liabilities {
          label
          value
        }
        accountTotals {
          type
          total
        }
      }
    }
  }
}"#;

/// Money movements — deposits, withdrawals, ACAT transfers (schema- and
/// live-verified 2026-08-18).
///
/// `viewer.transfers.pastInstances` is a `TransferInstanceConnection`
/// (`pageInfo` + `edges`). `TransferInstance.status` is an **object**
/// (`TransferInstanceStatus { code isPending isComplete isCanceled isFailed }`),
/// not a scalar. Dates are RFC 3339 timestamps. The node `id` is a
/// `TransferInstance:{"transferId":...}` blob — decoded to the inner id, like
/// documents.
pub const TRANSFERS: &str = r#"query TransfersHistory($first: Int, $after: String) {
  viewer {
    transfers {
      pastInstances(first: $first, after: $after) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            title
            description
            amount
            startDate
            endDate
            isLiquidation
            status {
              code
              isPending
              isComplete
              isCanceled
              isFailed
            }
          }
        }
      }
    }
  }
}"#;

/// Accounts on the login.
///
/// The research claimed this connection had no `pageInfo`; the live schema says
/// otherwise (`AccountConnection` carries one), so the command follows cursors
/// like every other list. Money fields live under `balance`
/// (`AccountBalance`), not the guessed `value` object: `totalValue.value` and
/// `cash.available` are plain `Float`s.
pub const ACCOUNTS: &str = r#"query AccountsPage($first: Int, $after: String) {
  viewer {
    accounts(first: $first, after: $after) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          id
          name
          nickname
          registration
          isRetirement
          status
          isActive
          isFunded
          balance {
            totalValue {
              value
              hasValue
            }
            cash {
              available
            }
          }
        }
      }
    }
  }
}"#;

/// Positions held in one account.
///
/// Positions do **not** hang off `Account` directly — the path is
/// `Account.balance.investments.positions` (schema-verified). Cost and value
/// are nested objects: `cost { cost averageSharePrice }`,
/// `value { value priceDate }`, `unrealizedGain { gain gainPercent }`, all
/// `Float`s.
pub const HOLDINGS: &str = r#"query InvestmentsTablePagination($accountId: ID!, $first: Int, $after: String) {
  node(id: $accountId) {
    ... on Account {
      id
      balance {
        investments {
          positions(first: $first, after: $after) {
            total
            pageInfo {
              hasNextPage
              endCursor
            }
            edges {
              cursor
              node {
                id
                quantity
                cost {
                  cost
                  averageSharePrice
                }
                value {
                  value
                  priceDate
                }
                unrealizedGain {
                  gain
                  gainPercent
                }
                dividends {
                  dividendYield
                  yieldOnCost
                  dividendFrequency
                  lastTwelveMonthsPaid
                }
                security {
                  symbol
                  name
                }
              }
            }
          }
        }
      }
    }
  }
}"#;

/// Account activity.
///
/// The path is `Account.investActivity.activity` (the guessed
/// `Account.activity` does not exist). `InvestActivityEntry` is an
/// **interface with seven implementations** — Trade, TradeSummary, Cash,
/// Position, Rebalance, Order, Other — not the 4-variant union the research
/// assumed. `id date title description` are interface fields, selected once;
/// the fragments add only what each variant genuinely owns. An unrecognized
/// eighth variant still renders via the interface fields plus `__typename`.
pub const ACTIVITY: &str = r#"query InvestActivityById($accountId: ID!, $first: Int, $after: String) {
  node(id: $accountId) {
    ... on Account {
      id
      investActivity {
        activity(first: $first, after: $after) {
          pageInfo {
            hasNextPage
            endCursor
          }
          edges {
            node {
              __typename
              id
              date
              title
              description
              ... on InvestActivityTradeEntry {
                isBuy
                quantity
                sharePrice
                amount
                tradeSecurity {
                  symbol
                }
              }
              ... on InvestActivityTradeSummaryEntry {
                countOfBuys
                countOfSells
                amountOfBuys
                amountOfSells
              }
              ... on InvestActivityCashEntry {
                amount
                cashSecurity {
                  symbol
                }
              }
              ... on InvestActivityPositionEntry {
                quantity
                positionSecurity {
                  symbol
                }
              }
            }
          }
        }
      }
    }
  }
}"#;

/// Dividend payments in one account, via the activity feed's server-side
/// category filter.
///
/// Observed live 2026-09-23: `InvestActivity.activity` takes a `filter:
/// InvestActivityEntryFilterInput` whose `includeCategoryDividend: true`
/// narrows the feed to dividend entries only — each an
/// `InvestActivityCashEntry` titled "Dividend" with an empty `description`.
/// `fromDate`/`toDate` take ISO dates and are inclusive at both ends. The
/// cash entry has no typed kind of its own, so the filter is the typed read;
/// matching on the title would be a keyword guess.
pub const DIVIDENDS: &str = r#"query InvestDividends($accountId: ID!, $first: Int, $after: String, $filter: InvestActivityEntryFilterInput) {
  node(id: $accountId) {
    ... on Account {
      id
      investActivity {
        activity(first: $first, after: $after, filter: $filter) {
          pageInfo {
            hasNextPage
            endCursor
          }
          edges {
            node {
              __typename
              id
              date
              title
              description
              ... on InvestActivityCashEntry {
                amount
                cashSecurity {
                  symbol
                }
              }
            }
          }
        }
      }
    }
  }
}"#;

/// The FDX (Financial Data Exchange) transaction ledger for one account —
/// schema- and live-verified 2026-08-18.
///
/// Distinct from `activity` (M1's own activity view) and `transfers` (cash in
/// and out): this is the industry-standard *normalized* per-transaction feed,
/// the cleanest source for tax and aggregation. `FdxTransaction` is an
/// interface (Investment / Deposit / Loan / LineOfCredit); the interface fields
/// (`id amount category subCategory description debitCreditMemo status
/// transactionTimestamp`) cover every variant, and the fragments add what each
/// owns — the Investment variant carries `symbol units unitPrice
/// transactionType commission fees`, the Deposit variant a `payee`. Amounts
/// are `Float`; `debitCreditMemo` is DEBIT / CREDIT / MEMO; `status` is
/// AUTHORIZATION / MEMO / PENDING / POSTED. Newest-first.
///
/// **Aliased on purpose** (live finding, 2026-08-18): each variant's
/// `transactionType` returns a *different* enum
/// (`FdxInvestmentTransactionTypeEnum` vs `FdxDepositTransactionTypeEnum`), and
/// GraphQL refuses two fragment fields of the same name with conflicting types
/// ("Use different aliases…"). So they are selected as `investmentType` /
/// `depositType`; the DTO reads whichever is present.
pub const TRANSACTIONS: &str = r#"query AccountTransactions($accountId: ID!, $first: Int, $after: String) {
  node(id: $accountId) {
    ... on Account {
      id
      fdxTransactions(first: $first, after: $after) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            __typename
            id
            amount
            category
            subCategory
            description
            debitCreditMemo
            status
            transactionTimestamp
            postedTimestamp
            ... on FdxInvestmentTransaction {
              symbol
              units
              unitPrice
              investmentType: transactionType
              commission
              fees
            }
            ... on FdxDepositTransaction {
              payee
              depositType: transactionType
            }
          }
        }
      }
    }
  }
}"#;

/// A per-account financial snapshot — schema- and live-verified 2026-08-18.
///
/// Rolls up the account-level figures scattered under `balance`: total value
/// and cash (already in `accounts list`) plus the ones nothing else surfaces —
/// `balance.investments.totalCost.cost`, `.totalValue.value`, and
/// `.totalUnrealizedGain { gain gainPercent }` (the "this account is up X%"
/// signal) — alongside `fundingTotals.totalsByYear` (lifetime deposits vs
/// withdrawals). `isPartial`/`hasValue` flag figures M1 itself couldn't fully
/// price. All `Float`.
pub const ACCOUNT_SUMMARY: &str = r#"query AccountSummary($accountId: ID!) {
  node(id: $accountId) {
    ... on Account {
      id
      name
      nickname
      registration
      balance {
        totalValue {
          value
          hasValue
        }
        cash {
          available
        }
        investments {
          totalCost {
            cost
          }
          totalValue {
            value
          }
          totalUnrealizedGain {
            gain
            gainPercent
            isPartial
          }
        }
      }
      fundingTotals {
        totalsByYear {
          year
          totalDeposits
          totalWithdrawals
        }
      }
    }
  }
}"#;

/// IRA contribution tracking for one account — schema- and live-verified
/// 2026-08-18.
///
/// `Account.iraContributionTotals.totalsByYear` is a `[{ year,
/// totalContribution, maxContribution }]` list (Floats), and
/// `iraContributionLimits.currentYearLimit` the current-year cap. These fields
/// exist on every `Account`, but only an IRA returns meaningful figures — the
/// command reads `registration` alongside to say so. Tax-relevant: it answers
/// "how much room is left in my IRA this year."
pub const IRA_CONTRIBUTIONS: &str = r#"query IraContributions($accountId: ID!) {
  node(id: $accountId) {
    ... on Account {
      id
      registration
      iraContributionLimits {
        currentYearLimit
      }
      iraContributionTotals {
        totalsByYear {
          year
          totalContribution
          maxContribution
        }
      }
    }
  }
}"#;

/// What is queued in one account and when it trades, schema-verified by
/// introspection on 2026-11-04 and not yet exercised live (docs/api.md,
/// "Trading status").
///
/// `PortfolioSlice.to` is the `Sliceable` interface, which has no `symbol`: a
/// `Security` has one, and so does `MutualFund`, which is a `Sliceable` but not
/// a `Security`. A pie has only a name.
///
/// A rebalance's lock lives in `rebalanceStatus`, so the fragment selects both
/// statuses. `netDescendant*` leave out an order on the root slice itself, so
/// the root's own `order` is selected beside them.
pub const ACCOUNT_TRADING: &str = r#"query AccountTrading($accountId: ID!, $first: Int) {
  node(id: $accountId) {
    ... on Account {
      id
      name
      nickname
      registration
      isRetirement
      status
      isLiquidating
      isTradingPaused
      tradingPause {
        title
        description
      }
      maxCashThreshold
      autoInvestTriggerMinimum
      trading {
        isInProgress
        inProgressWindowForAccount
        nextTradingTime
        nextWindowForAccount
        hasAccessToNextAfternoonWindow
      }
      portfolioSlicesWithSellOrders {
        ...TradingSlice
      }
      portfolioSlicesWithBuyOrders {
        ...TradingSlice
      }
      portfolioSlicesWithRebalances {
        ...TradingSlice
      }
      rootPortfolioSlice {
        orderStatus {
          netDescendantSellOrderAmount
          netDescendantBuyOrderAmount
          order {
            cashFlow
          }
        }
      }
      imminentPendingCashFlowForOrders
      estimatedTrading {
        hasTrades
        totalSellAmount
        totalBuyAmount
        lastEstimatedTime
        sells(first: $first) {
          ...TradingEstimates
        }
        buys(first: $first) {
          ...TradingEstimates
        }
      }
      balance {
        totalValue {
          value
          hasValue
        }
        cash {
          available
          availableForWithdrawal
        }
      }
      hasPendingTransferInstances
      pendingTransferInstanceSummary
      pendingTransferInstances {
        id
        status {
          code
        }
        title
        description
        startDate
        endDate
        amount
        isLiquidation
        isCheck
        dependsOnSells
        timingDescription
        iraDistributionReason
        from {
          transferParticipantType
          transferParticipantName
        }
        to {
          transferParticipantType
          transferParticipantName
        }
      }
    }
  }
}

fragment TradingSlice on PortfolioSlice {
  isRootSlice
  to {
    name
    ... on Security {
      symbol
    }
    ... on MutualFund {
      symbol
    }
  }
  value {
    total
  }
  orderStatus {
    isLocked
    lockReason
    order {
      cashFlow
    }
  }
  rebalanceStatus {
    isLocked
    lockReason
  }
}

fragment TradingEstimates on EstimatedTradeAmountConnection {
  total
  pageInfo {
    hasNextPage
    endCursor
  }
  edges {
    node {
      amount
      isBuy
      of {
        symbol
        name
      }
      pill {
        label
      }
    }
  }
}"#;

/// The later pages of one account's estimated trades, one side at a time. Each
/// side has its own cursor, and asking again for a finished side would restart it.
pub const ACCOUNT_ESTIMATED_TRADES: &str = r#"query AccountEstimatedTrades($accountId: ID!, $first: Int, $sellsAfter: String, $buysAfter: String, $withSells: Boolean!, $withBuys: Boolean!) {
  node(id: $accountId) {
    ... on Account {
      estimatedTrading {
        sells(first: $first, after: $sellsAfter) @include(if: $withSells) {
          ...TradingEstimates
        }
        buys(first: $first, after: $buysAfter) @include(if: $withBuys) {
          ...TradingEstimates
        }
      }
    }
  }
}

fragment TradingEstimates on EstimatedTradeAmountConnection {
  total
  pageInfo {
    hasNextPage
    endCursor
  }
  edges {
    node {
      amount
      isBuy
      of {
        symbol
        name
      }
      pill {
        label
      }
    }
  }
}"#;

/// Statements, trade confirmations, and tax forms.
///
/// `Document` is an interface (`InvestAccountDocument` / `AccountDocument` /
/// `SpendAccountDocument`); `id date type name accountName` are interface
/// fields. The guessed `title`/`category`/`fileName` do not exist. `type` is a
/// `DocumentTypeEnum` (STATEMENT, TAX_FORM, TRADE_CONFIRMATION,
/// INVESTMENTS_RELATED, ACCOUNT_DOCUMENT) — TAX_FORM is the 1099 filter.
///
/// `InvestAccountDocument.url` exists but is deliberately NOT selected: it is
/// pre-signed and expires, i.e. a live credential. Downloads mint a fresh one
/// via `CreateAccountDocumentLink` instead.
pub const DOCUMENTS: &str = r#"query DocumentList($first: Int, $after: String, $documentType: DocumentTypeFilterEnumType, $startDate: String, $endDate: String) {
  viewer {
    documents(first: $first, after: $after, documentType: $documentType, startDate: $startDate, endDate: $endDate) {
      pageInfo {
        hasNextPage
        endCursor
      }
      edges {
        node {
          __typename
          id
          date
          type
          name
          accountName {
            label
            subLabel
          }
        }
      }
    }
  }
}"#;

/// Mint a fresh signed download link for a document.
///
/// **This is a mutation, and `m1f` sends it** — see the read-only note in
/// SECURITY.md. It creates a short-lived download URL and changes no account
/// state: no money moves, no order is placed, no setting changes. It exists
/// because the `url` on `InvestAccountDocument` is pre-signed and expires, so a
/// listing fetched minutes ago can carry a dead link.
///
/// The input field is `accountDocumentId` (schema-verified; the first guess of
/// `documentId` was wrong). Its error enum has one member, and M1 spells it
/// `DOCUMENT_NOT_AVAILBLE` — their typo, preserved here so nobody "fixes" a
/// match against it.
pub const CREATE_DOCUMENT_LINK: &str = r#"mutation CreateAccountDocumentLink($input: CreateAccountDocumentLinkInput!) {
  createAccountDocumentLink(input: $input) {
    didSucceed
    error
    outcome {
      url
    }
  }
}"#;

/// Per-lot cost basis, acquisition dates, realized/unrealized gain, and
/// wash-sale data — the richest tax surface M1 exposes, strictly better than
/// the 1099 PDF for reconstructing Form 8949.
///
/// Schema-verified: the flag is `washSaleIndicator` (not the guessed
/// `isWashSale`), gains are split `shortTermRealizedGainLoss` /
/// `longTermRealizedGainLoss`. All quantities and dollar figures are
/// `Float`s; dates are `String`s.
///
/// `lotType` is **required** (`LotTypeEnum!` — verified live; the resolver
/// rejects a nullable variable): there is no single "all lots" call, so the
/// command queries OPEN and CLOSED separately and merges.
pub const ACCOUNT_TAX_LOTS: &str = r#"query AccountTaxLots($accountId: ID!, $first: Int, $after: String, $lotType: LotTypeEnum!) {
  node(id: $accountId) {
    ... on Account {
      id
      taxLots(first: $first, after: $after, lotType: $lotType) {
        totalCount
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          cursor
          node {
            id
            symbol
            cusip
            acquisitionDate
            quantity
            costBasis
            shortLongTermHolding
            closeDate
            shortTermRealizedGainLoss
            longTermRealizedGainLoss
            unrealizedGainLoss
            washSaleIndicator
            disallowedWashSaleAmount
          }
        }
      }
    }
  }
}"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Query,
    Mutation,
    Subscription,
}

impl OperationKind {
    fn name(self) -> &'static str {
        match self {
            OperationKind::Query => "query",
            OperationKind::Mutation => "mutation",
            OperationKind::Subscription => "subscription",
        }
    }
}

/// Replace comment and string-literal content with spaces, preserving byte
/// positions and all structural punctuation outside them. Block strings
/// (`"""…"""`) and escapes are handled so a `"` inside a string can't
/// desynchronize the scan.
fn blank_ignored(doc: &str) -> String {
    let c: Vec<char> = doc.chars().collect();
    let mut out = String::with_capacity(c.len());
    let mut i = 0;
    while i < c.len() {
        // Comment: to end of line.
        if c[i] == '#' {
            while i < c.len() && c[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if c[i] == '"' {
            // Block string """…"""
            if i + 2 < c.len() && c[i + 1] == '"' && c[i + 2] == '"' {
                out.push_str("   ");
                i += 3;
                while i < c.len() {
                    if c[i] == '"' && i + 2 < c.len() && c[i + 1] == '"' && c[i + 2] == '"' {
                        out.push_str("   ");
                        i += 3;
                        break;
                    }
                    // Keep newlines so line-based tooling stays aligned.
                    out.push(if c[i] == '\n' { '\n' } else { ' ' });
                    i += 1;
                }
                continue;
            }
            // Ordinary string.
            out.push(' ');
            i += 1;
            while i < c.len() {
                if c[i] == '\\' {
                    out.push(' ');
                    i += 1;
                    if i < c.len() {
                        out.push(' ');
                        i += 1;
                    }
                    continue;
                }
                if c[i] == '"' {
                    out.push(' ');
                    i += 1;
                    break;
                }
                if c[i] == '\n' {
                    // Unterminated string; stop rather than swallow the document.
                    break;
                }
                out.push(' ');
                i += 1;
            }
            continue;
        }
        out.push(c[i]);
        i += 1;
    }
    out
}

/// The operations a document declares, in order.
///
/// A bare selection set (`{ viewer { id } }`) is GraphQL's shorthand for an
/// anonymous query and counts as one.
pub fn operations(doc: &str) -> Vec<OperationKind> {
    let s = blank_ignored(doc);
    let c: Vec<char> = s.chars().collect();
    let mut depth: i32 = 0;
    let mut ops = Vec::new();
    let mut word = String::new();
    // True once a keyword has claimed the next depth-0 `{`, so we don't also
    // count that selection set as an anonymous-query shorthand.
    let mut claimed = false;

    let flush = |word: &mut String, ops: &mut Vec<OperationKind>, claimed: &mut bool| {
        match word.as_str() {
            "query" => {
                ops.push(OperationKind::Query);
                *claimed = true;
            }
            "mutation" => {
                ops.push(OperationKind::Mutation);
                *claimed = true;
            }
            "subscription" => {
                ops.push(OperationKind::Subscription);
                *claimed = true;
            }
            "fragment" => *claimed = true,
            _ => {}
        }
        word.clear();
    };

    for &ch in &c {
        if ch.is_alphanumeric() || ch == '_' {
            if depth == 0 {
                word.push(ch);
            }
            continue;
        }
        if depth == 0 && !word.is_empty() {
            flush(&mut word, &mut ops, &mut claimed);
        }
        match ch {
            '{' => {
                if depth == 0 && !claimed {
                    // Shorthand anonymous query.
                    ops.push(OperationKind::Query);
                }
                depth += 1;
            }
            '(' | '[' => depth += 1,
            '}' => {
                depth -= 1;
                if depth <= 0 {
                    depth = 0;
                    claimed = false;
                }
            }
            ')' | ']' => {
                depth -= 1;
                if depth < 0 {
                    depth = 0;
                }
            }
            _ => {}
        }
    }
    if depth == 0 && !word.is_empty() {
        flush(&mut word, &mut ops, &mut claimed);
    }
    ops
}

/// Refuse anything that isn't a read.
///
/// Returns `CliError::Usage` (exit 2) rather than a confirmation error: this
/// isn't a "are you sure" gate that `--force` can open, it's outside what this
/// tool does at all.
pub fn guard_read_only(doc: &str) -> Result<(), CliError> {
    let ops = operations(doc);
    if ops.is_empty() {
        return Err(CliError::Usage(
            "no GraphQL operation found in the document".into(),
        ));
    }
    if let Some(bad) = ops
        .iter()
        .find(|o| !matches!(o, OperationKind::Query))
        .copied()
    {
        return Err(CliError::Usage(format!(
            "`m1f` is read-only and refuses to send a GraphQL {} — only `query` \
             operations are allowed through `api query`",
            bad.name()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every document a read sends is a query, so a read cannot reach a mutation.
    #[test]
    fn every_read_document_passes_the_read_only_guard() {
        for doc in [
            SYSTEM_STATUS,
            VIEWER_IS_AUTHENTICATED,
            NET_WORTH,
            TRANSFERS,
            ACCOUNTS,
            HOLDINGS,
            ACTIVITY,
            DIVIDENDS,
            TRANSACTIONS,
            ACCOUNT_SUMMARY,
            IRA_CONTRIBUTIONS,
            ACCOUNT_TRADING,
            ACCOUNT_ESTIMATED_TRADES,
            DOCUMENTS,
            ACCOUNT_TAX_LOTS,
        ] {
            assert!(guard_read_only(doc).is_ok(), "{doc}");
            assert_eq!(operations(doc), vec![OperationKind::Query], "{doc}");
        }
    }

    #[test]
    fn plain_query_is_allowed() {
        assert!(guard_read_only("query Accounts { viewer { id } }").is_ok());
        assert_eq!(
            operations("query Accounts { viewer { id } }"),
            vec![OperationKind::Query]
        );
    }

    #[test]
    fn shorthand_selection_set_is_a_query() {
        assert_eq!(operations("{ viewer { id } }"), vec![OperationKind::Query]);
        assert!(guard_read_only("{ viewer { id } }").is_ok());
    }

    #[test]
    fn mutation_is_refused() {
        let err = guard_read_only("mutation Sell { sellAll { ok } }").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("read-only"), "{err}");
        assert!(err.to_string().contains("mutation"), "{err}");
    }

    #[test]
    fn subscription_is_refused() {
        let err = guard_read_only("subscription S { ticks { price } }").unwrap_err();
        assert!(err.to_string().contains("subscription"), "{err}");
    }

    #[test]
    fn a_field_named_mutation_is_not_an_operation() {
        // `mutation` is a perfectly legal field name; it sits at depth > 0.
        assert!(guard_read_only("query Q { mutation { id } }").is_ok());
    }

    #[test]
    fn mutation_inside_a_comment_or_string_is_ignored() {
        assert!(guard_read_only("# mutation Sell { x }\n{ viewer { id } }").is_ok());
        assert!(guard_read_only(r#"query Q { search(term: "mutation") { id } }"#).is_ok());
        assert!(guard_read_only("query Q { f(t: \"\"\"mutation\"\"\") { id } }").is_ok());
    }

    #[test]
    fn a_variable_named_mutation_is_ignored() {
        assert!(guard_read_only("query Q($mutation: String) { f(a: $mutation) { id } }").is_ok());
    }

    #[test]
    fn a_mutation_hiding_after_a_fragment_or_query_is_caught() {
        let doc =
            "fragment F on Account { id }\nquery Q { a { ...F } }\nmutation M { sell { ok } }";
        let err = guard_read_only(doc).unwrap_err();
        assert!(err.to_string().contains("mutation"), "{err}");
        let doc2 = "query A { x }\nmutation B { y }";
        assert!(guard_read_only(doc2).is_err());
    }

    #[test]
    fn fragment_only_document_has_no_operation() {
        let err = guard_read_only("fragment F on Account { id }").unwrap_err();
        assert!(err.to_string().contains("no GraphQL operation"), "{err}");
    }

    #[test]
    fn empty_document_is_a_usage_error() {
        assert!(guard_read_only("").is_err());
        assert!(guard_read_only("   \n # just a comment\n").is_err());
    }

    #[test]
    fn multiple_queries_are_fine() {
        assert_eq!(
            operations("query A { x }\nquery B { y }"),
            vec![OperationKind::Query, OperationKind::Query]
        );
    }
}
