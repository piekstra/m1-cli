# M1's API: surfaces, auth, and traps

**Status: verified against a live account on 2026-08-13.** The unauthenticated
probe, full-schema introspection, password + email-code login, and every read
command (accounts, holdings, activity, documents — including a real
consolidated-1099 PDF download — and per-lot tax data) have all been exercised
for real. The UNVERIFIED-LIVE table that used to dominate this file is now empty;
what genuinely remains unknown is a short list at the bottom.
A second live session on **2026-09-23** added the dividend category filter,
the position and activity id blobs, and `isRetirement` (sections below).
On **2026-10-27** the password login started answering a Cloudflare 403
([Trap 7](#trap-7-the-password-login-answers-a-cloudflare-403)); the
[Auth0 session](#2-auth0--accountm1com) M1's web app now uses was read from
its public bundle and metadata the same day, with no login attempted.
`m1f auth login --browser` takes that session out of a Chrome window the
owner signs in through ([The browser capture](#the-browser-capture-auth-login---browser)).

**The single most useful fact discovered live: `lens.m1.com` answers GraphQL
introspection queries without authentication.** The complete schema — every
type, field, argument, scalar, and enum — was pulled with a plain
`m1f api query '{ __schema { … } }'` before any login. Everything below that
says "schema-verified" comes from that dump; everything that says "observed
live" comes from running the real commands against the account.

M1 Holdings publishes **no public API**. There is no `developer.m1.com` (the
host does not resolve), `m1.com/developers` is a 404, and M1's help center has
no API article. Everything here talks to the private GraphQL backend behind
M1's own web app.

---

## The surfaces

### 1. GraphQL — `https://lens.m1.com/graphql`

One endpoint, POST only. This is what M1's own web dashboard talks to. It is
fronted by **Cloudflare bot management** (the `__cf_bm` cookie) — but, verified
live, the raw `reqwest` client passes straight through with the headers below.
No browser-session token capture was needed; `{ __typename }` returned
`"Query"` on the first try.

| Header | Value | Note |
| --- | --- | --- |
| `content-type` | `application/json` | |
| `apollographql-client-name` | `m1-web` | |
| `x-apollo-operation-name` | the operation name | |
| `origin` / `referer` | `https://dashboard.m1.com` | |
| `authorization` | `Bearer <accessToken>` | **Confirmed live** — reads succeed with the bearer, fail without. Since the Auth0 move the token is an Auth0 access token (surface 2). |

`m1f` also sends `x-client-id` (`m1-web/10.0.312`, the version in the
dashboard bundle's Apollo link on 2026-10-27; `10.0.272` on 2026-08-13),
`x-client-sentinel` (epoch ms), and `x-segment-id` (a stable machine-derived
UUIDv4). Whether their absence triggers a challenge is still unverified — they
cost nothing and are kept.

How an unauthenticated or refused bearer reads (observed 2026-10-27 with no
token and with a bogus one, both alike): an account read answers HTTP 200 with
`errors: [{ isAuthError: true, code: "AUTH_ERROR", message: "Not authorized."
}]` and `data.viewer.accounts: null`, which `classify_errors` maps to exit 3;
`viewer { isAuthenticated }` answers `false` with **no** error. That flag is
the browser-session login's verification read.

The live `system.version` at capture time was **2.158.172** (distinct from the
`x-client-id` app version).

### 2. Auth0 — `account.m1.com`

M1's web dashboard signs in through Auth0, not the `Authenticate` mutation.
Read on 2026-10-27 from the public bundle (`dashboard.m1.com` →
`/assets/index-*.js`) — no login attempted:

| Setting | Value |
| --- | --- |
| SDK | `@auth0/auth0-spa-js` (`new Auth0Client({…})`) |
| `domain` | `account.m1.com` (M1's custom Auth0 domain; staging `account.m1.dev`, develop `m1-develop.us.auth0.com`) |
| `clientId` | `1Gz7GHj4BiQ9lTQgVpleNuzUHl2KQnYI` (a public SPA client) |
| `authorizationParams.audience` | `https://lens.m1finance.com` |
| `authorizationParams.scope` | `openid profile email offline_access exchange:exchange:read` |
| `cacheLocation` | `localstorage` |
| `useRefreshTokens` | `true` |

The Apollo link builds its headers as `{"X-Client-Id": "m1-web/10.0.312",
"X-Client-Sentinel": Date.now(), "X-Segment-Id": …, Authorization: "Bearer " +
await auth0.getTokenSilently(), "X-Client-Timezone": …,
"X-Apollo-Operation-Name": …}` against `window.config.graphql.endpoint` =
`https://lens.m1.com/graphql` — so the GraphQL endpoint takes the **Auth0
access token** as its bearer. (Only the three two-factor-settings mutations
use a separate in-memory token.)

`https://account.m1.com/.well-known/openid-configuration` (public) names the
token endpoint `https://account.m1.com/oauth/token`, lists the
`refresh_token` grant, and lists `none` among the token-endpoint auth
methods — a public client renews without a secret.

**Where the session lives.** auth0-spa-js with `cacheLocation: localstorage`
keeps its token cache in the dashboard's localStorage under
`@@auth0spajs@@::<clientId>::<audience>::<scope>`; the value is

```json
{ "body": { "access_token": "…", "refresh_token": "…", "expires_in": 86400,
            "token_type": "Bearer", "audience": "https://lens.m1finance.com",
            "client_id": "…", "scope": "…", "id_token": "…", "decodedToken": {…} },
  "expiresAt": 1900000000 }
```

(`expires_in` and `expiresAt` above are the fixture's dummies; the real
lifetime is not yet observed.) `tests/fixtures/auth/auth0-spa-cache.json` is a
synthetic copy of the shape.

**How `m1f` uses it** (`src/auth0.rs`):

1. The session reaches `m1f` by one of two routes, which store the same
   thing:
   - **`m1f auth login --browser`** (the primary route): a Chrome window
     opens at dashboard.m1.com, the owner signs in there, and `m1f` reads the
     cache entry's value out of the page ([The browser
     capture](#the-browser-capture-auth-login---browser), below).
   - **`m1f auth login --browser-session --stdin`** (the fallback, for a
     machine without Chrome): the owner signs in at dashboard.m1.com in a
     private window, copies the cache entry with a one-line DevTools snippet
     (in `m1f auth login --help`) and pipes it in: `pbpaste | m1f auth login
     --browser-session --stdin`. The value is several kilobytes, past the
     1024-byte line a macOS terminal takes, so it is read from
     `--stdin`/`--from-env` only, never a prompt.
2. One reader takes either (`auth0::parse_browser_capture` and
   `auth0::parse_captured` share it and differ only in how a refusal is
   reported). It accepts the cache
   entry, the whole localStorage map (`JSON.stringify(localStorage)`), an
   Auth0 token response, or a bare `Bearer …` header copied from the Network
   tab (no refresh token: it lasts until it expires). It refuses a token whose
   `aud` is not `https://lens.m1finance.com` or whose `iss` is not
   `account.m1.com`. Only the access token, refresh token, expiry and client
   id are kept — the id token and the profile in `decodedToken` are dropped.
   A pasted value it refuses is exit 2 with what to copy instead; a captured
   one is exit 5 naming what was wrong, since that means M1 changed how its
   web app keeps the session.
3. One read, `viewer { isAuthenticated }`, must answer `true` before anything
   is stored (`--no-verify` skips it). An access token already expired is
   renewed first.
4. On an auth failure, a read renews the session at
   `https://account.m1.com/oauth/token` (`grant_type=refresh_token`,
   `client_id`, `refresh_token`, form-encoded, `Origin:
   https://dashboard.m1.com`), keeps the rotated refresh token, and retries
   once. `invalid_grant` is exit 3 naming the recapture (`m1f auth login
   --browser --overwrite`); 429, an HTML answer and 5xx are exit 5.

`auth status` reports `method: browser-session` for a session from either
route: the stored bundle records that it came from Auth0 (its `auth0` field,
which says where it renews), not which route handed it over.

**The shared-refresh-token trap.** Auth0 tenants normally rotate refresh
tokens, and answer the reuse of a retired one by revoking the whole family. A
session copied out of a browser that stays open is held twice: whichever of
the browser or `m1f` renews second presents a retired token, and both lose the
session. The browser capture closes the dashboard tab the moment it has read
the session, before the web app can renew, then quits Chrome and deletes its
profile. The DevTools route relies on the owner: a private window, closed
after copying **without signing out** (signing out may revoke the session
`m1f` now holds).

#### The browser capture (`auth login --browser`)

The mechanism is cli-common's `pk-cli-browser` (its DESIGN.md §2.2); what
`m1f` adds is which page to open, where to read, and what.

| | |
| --- | --- |
| Launch URL | `https://dashboard.m1.com` (`client::WEB_ORIGIN`). Chrome starts with only a debug port of its own choosing, a scratch `0700` profile and first-run suppression, so the page sees an ordinary browser. `M1F_CHROME` overrides which Chrome binary. |
| Sign-in | The dashboard sends the owner to Auth0's page on `account.m1.com`: password and any emailed code are typed there, never into `m1f`. That host is never read from. |
| Read from | Pages on exactly `dashboard.m1.com` (`HostRule::exact`): `https` on the default port, matched label by label, so `account.m1.com`, `m1.com` and look-alike hosts are not read. |
| What is read | This expression, evaluated in those pages (`auth0::CAPTURE_EXPRESSION`): |
| Ready when | The expression answers with a string: the cache entry for M1's API exists and holds an `access_token`, which is only true once the owner is signed in. Before that it answers `null` and the capture keeps waiting (up to 10 minutes; Ctrl-C cancels). |
| Then | Every dashboard tab is closed at once, Chrome is stopped and the profile deleted. The value goes through the same reader, check and store as a piped session. |

```js
(() => { const k = Object.keys(localStorage).find(k => k.startsWith('@@auth0spajs@@::') && k.includes('lens.m1finance.com')); const v = k && localStorage[k]; return v && v.includes('access_token') ? v : null; })()
```

The value it returns is the one the DevTools snippet copies: the
localStorage entry under `@@auth0spajs@@::<clientId>::https://lens.m1finance.com::<scope>`,
a string of the JSON shape above. A unit test holds the expression to the
prefix and audience the reader looks for, and to this page.

A timeout or a window closed before the sign-in finished is exit 3 naming
the command to re-run; no Chrome found is exit 1 pointing at the DevTools
route.

### 3. Document downloads — two hosts, both pre-signed

Documents are PDFs served from storage hosts, **not** from `lens.m1.com`:

- **Self-clearing (post-2023) docs** → Google Cloud Storage
  (`storage.googleapis.com/prj-p-iris-m1-…`), with a `X-Goog-Expires=900`
  (15-minute) signature.
- **Apex-era (pre-2023, and still-Apex IRA) docs** → Apex's
  `edocuments.apexclearing.com/RedirectConfirmURL.aspx`.

**A document URL is a live credential**, pre-signed and short-lived. It must
never be logged, committed to a fixture, or emitted in `--json`. The
`documents/v1` DTO has no URL field, and — see Trap 5 — the URL is not even
kept in the node id that *is* emitted.

---

## Trap 1: the HTTP status tells you nothing

GraphQL answers **`200 OK` for failure**. Success is the absence of a populated
`errors` array plus the data you asked for. `client::execute` inspects `errors`
*before* status; status is only consulted afterward to catch infra failures (a
502) that never reached the GraphQL layer. Partial data alongside `errors` is
still a failure — any populated `errors` array is.

## Trap 2: a clean envelope that still means "no"

`Authenticate` returns `{ didSucceed, error, expiresIn, outcome { accessToken
refreshToken } }`. Verified live:

- **`error` is an `AuthenticateErrorEnum`** (schema-verified), not free text.
  Members: `INCORRECT_CREDENTIALS`, `USER_ACCOUNT_LOCKED`, `CODE_REQUIRED`,
  `EMAIL_AMFA_REQUIRED`, `AMFA_TOKEN_EXPIRED`, `INCORRECT_AMFA_CODE`,
  `INCORRECT_CODE`, `AGREEMENT_REQUIRED`, `CLIENT_VERSION_NOT_SUPPORTED`.
- **`outcome` is a plain object (`AuthenticateOutcome`)**, no challenge variant.
- A **wrong password returns HTTP 200 with no `errors` array at all** —
  confirmed live: the login attempt came back `didSucceed: false`,
  `error: "INCORRECT_CREDENTIALS"`, `outcome: null`, and `m1f` reported exit 3
  honestly rather than storing an empty token.

`client::check_did_succeed` enforces this on every payload carrying the flag.

## Trap 3: HTML where JSON should be

A Cloudflare challenge returns an HTML interstitial, not GraphQL. `m1f` detects
a non-JSON body and reports it as an auth failure pointing at `m1f auth login`.
Not seen live in this session, but the guard stays.

## Trap 4: M1 puts the error code at the TOP LEVEL, not under `extensions`

This is the big correction from live capture. M1 does **not** follow the Apollo
`extensions.code` convention. A real error object looks like:

```json
{ "isAuthError": false, "name": "GraphQLError",
  "code": "GRAPHQL_VALIDATION_FAILED", "http": { "status": 400 },
  "message": "Cannot query field \"nope\" on type \"Viewer\"." }
```

`code` sits at the top level, alongside an **`isAuthError`** boolean and an
`http.status`. `client::classify_errors` reads `extensions.code` first (for a
conventional gateway) then the top-level `code`, and short-circuits on
`isAuthError: true`.

## Trap 5: the document node `id` is itself a credential

`Document.id` is **not** an opaque handle. It is base64 of
`InvestAccountDocument:{"document":{…}}`, and the inner payload embeds the
**account number** and a **pre-signed download URL**. It is also *unstable* —
every listing re-signs the URL, so the same document gets a different `id` blob
each run. `m1f` decodes the blob, emits only the **stable inner document id**,
and keeps the account number and URL out of band. `documents download <ID>`
matches on that inner id.

## Failure is dual-channel

| Channel | Looks like | Means |
| --- | --- | --- |
| Transport / GraphQL | HTTP 200 + top-level `errors[]` (with top-level `code`) | bad query, expired token, refused op |
| Business / auth | HTTP 200 + `data` + `didSucceed: false` + `error` enum | wrong password, MFA required |

## Trap 6 (context): the auth backend moved to Auth0

M1 stood up Auth0 (`login.auth.m1.com` was the first name seen; the web app's
configured domain is `account.m1.com` — surface 2). The `authenticate`
mutation here is the legacy path, and Trap 7 is what its retirement looks like
from outside. `TokenBundle` is storage-shaped, not tied to how the tokens were
obtained; an `auth0` field marks a browser-session bundle so a refresh goes to
the right place (`Reauthenticate` for a legacy bundle, Auth0's token endpoint
for a browser session). A bundle stored before that field existed reads as
legacy.

## Trap 7: the password login answers a Cloudflare 403

**Seen 2026-10-27.** `m1f auth login` got **HTTP 403 Forbidden with an HTML
page** (Cloudflare) in answer to the `Authenticate` mutation, while the
unauthenticated `m1f status` probe, minutes apart, answered `NORMAL` with
GraphQL. So the endpoint is up and anonymous reads pass the edge; the password
login does not. The dashboard bundle read the same day no longer sends
`Authenticate` at all — it signs in through Auth0 (surface 2) — which reads as
M1 retiring the legacy path at the edge rather than a transient bot check.
Whether the edge keys on the operation, the mutation, or the client was not
probed: every probe of it would be a password submission, which can lock the
account.

What `m1f` does with it:

- `auth login` (password) maps an HTML answer to exit 3 with a message naming
  this trap and the browser-session login, and stores nothing
  (`client::legacy_login_blocked`). It does **not** retry: a second password
  submission spends a lockout attempt for the same 403.
- Every other HTML answer (a read, a legacy refresh) is exit 3 pointing at
  `m1f auth login --browser --overwrite` (`client::html_error`).
- `info` reports `auth.method: browser-session` and `m1f auth login --browser`
  as the hint.

What the owner does: `m1f auth login --browser`, or without Chrome the four
DevTools steps in `m1f auth login --help` (and the README).

**Do not test this by logging in.** An agent may run the unauthenticated
probes (`m1f status`, introspection through `m1f api query` with no session);
any password submission, code, or token exchange against the live service is
the owner's to run.

---

## Operations (all schema-verified, all exercised live unless noted)

| Operation | Command | Notes |
| --- | --- | --- |
| `Authenticate` | `auth login` | `AuthenticateInput` fields: `username`, `password`, `emailCode`, `code`, `signature`, `mfaAudience`. `emailCode` is the email-MFA replay field (confirmed live). `code` is the separate TOTP field. |
| `Reauthenticate` | token refresh | `ReauthenticateInput { refreshToken }`; error enum `INVALID_REFRESH_TOKEN` / `USER_ACCOUNT_LOCKED`. Tokens rotate. **Live-verified 2026-08-18**: after the 24 h access token lapsed, the stored refresh token silently minted a fresh pair and the read succeeded. |
| `system` (`SystemInfo!`) | `status` | The real liveness probe (the guessed `checkSystemStatus` root field does **not** exist). `status` is `SystemStatusEnum` = NORMAL / DEGRADED / DISRUPTED / MAINTENANCE. Unauthenticated. Live value: NORMAL. |
| `AccountsPage` | `accounts list` | `viewer.accounts` — a real `AccountConnection` **with `pageInfo`** (the research guessed none). Money under `balance`: `totalValue { value hasValue }`, `cash { available }`, all `Float`. Registrations: INDIVIDUAL, JOINT, ROTH_IRA, TRADITIONAL_IRA, SEP_IRA, CUSTODIAL, TRUST, LLC, … Status: OPENED / NEW / CLOSED / REJECTED. |
| `InvestmentsTablePagination` | `holdings list`, `positions list` | Positions hang off **`Account.balance.investments.positions`**, not the account node. `cost { cost averageSharePrice }`, `value { value priceDate }`, `unrealizedGain { gain gainPercent }`, all `Float`. `quantity` is fractional `Float`. Enriched with `dividends { dividendYield yieldOnCost dividendFrequency lastTwelveMonthsPaid }` — yields are `Float` percentages; `lastTwelveMonthsPaid` is a **display string** M1 renders as `"$--"` when it has no figure (dropped, not shown). |
| `NetWorthOverview` | `net-worth` | `viewer.overview.balances` (`BalancesOverview`): `total` net worth, `assets`/`liabilities` as `NetWorthLabel { label value }`, `assetRatio`, `isPartialTotal`, and `accountTotals` — a `[{ type, total }]` breakdown by product line (Invest / Earn / Borrow / Spend). Live-verified 2026-08-18. `AccountTotalWithStatus` is only `{ type: String!, total: Float! }` (introspected 2026-10-27): the overview has no per-account figure, so `net-worth` reads the Invest line's accounts from `AccountsPage` — see "Net worth by account" below. |
| `ViewerIsAuthenticated` | `auth login --browser`, `auth login --browser-session` | `viewer { isAuthenticated }` (`Boolean`). `false`, with no error, for a missing or refused bearer (observed 2026-10-27); the browser-session login, by either route, stores a session only when it answers `true`. |
| `TransfersHistory` | `transfers list` | `viewer.transfers.pastInstances` (`TransferInstanceConnection`). `status` is an **object** (`TransferInstanceStatus { code isPending isComplete isCanceled isFailed }`), not a scalar; dates are RFC 3339. The node `id` is a `TransferInstance:{"transferId":…}` blob — decoded to the inner id, like documents. Live-verified 2026-08-18. |
| `InvestDividends` | `dividends list` | The same `Account.investActivity.activity` connection with `filter: { includeCategoryDividend: true, fromDate, toDate }` — see "Dividends: the typed read" below. Live-verified 2026-09-23. |
| `InvestActivityById` | `activity list` | Path is **`Account.investActivity.activity`**. `InvestActivityEntry` is an **interface with 7 implementations** (see below). |
| `AccountTransactions` | `transactions list` | `Account.fdxTransactions` — the FDX (Financial Data Exchange) *normalized* ledger, the richest transaction surface. `FdxTransaction` is an interface (Investment / Deposit / Loan / LineOfCredit); interface fields (`id amount category debitCreditMemo status transactionTimestamp`) cover every variant. **`transactionType` must be aliased** per variant (`investmentType` / `depositType`) — the two enums conflict and the server rejects the same field name ("Use different aliases…"). Live-verified 2026-08-18. |
| `DocumentList` | `documents list\|download` | `viewer.documents`. **Requires `documentType`, `startDate`, AND `endDate`** — see below. `Document` interface fields: `id date type name accountName{label subLabel}`. `type` is `DocumentTypeEnum`. |
| `CreateAccountDocumentLink` | `documents download` | Mints a link for the **ACCOUNT_DOCUMENT** class only; `accountDocumentId` (not `documentId`) takes the raw blob. **Refuses invest docs** ("Unexpected ID type, expected: AccountDocument. Received: InvestAccountDocument"), which is fine — invest docs carry their own embedded URL. Changes no account state. |
| `AccountTaxLots` | `lots list` | Per-lot cost basis — see below. |
| `AccountSummary` | `summary` | Per-account rollup under `balance`: `totalValue`, `cash.available`, and the figures nothing else surfaces — `investments.totalCost.cost`, `.totalValue.value`, `.totalUnrealizedGain { gain gainPercent }` — plus `fundingTotals.totalsByYear { totalDeposits totalWithdrawals }`. All `Float`; `hasValue: false` figures are omitted. Live-verified 2026-08-18. |
| `IraContributions` | `ira` | `Account.iraContributionTotals.totalsByYear` (`[{ year, totalContribution, maxContribution }]`, Floats) + `iraContributionLimits.currentYearLimit`. The command computes remaining room per year in **integer cents** (never float money math), clamped at zero. These fields exist on every account, so `ira` reads `registration` and reports a non-IRA account as such. Live-verified 2026-08-18. |

### Activity is a 7-member interface

`InvestActivityEntry` implementations: `Trade`, `TradeSummary`, `Cash`,
`Position`, `Rebalance`, `Order`, `Other`. `id date title description account`
are interface fields selected once; each fragment adds only what it owns
(`Trade` → `isBuy quantity sharePrice amount tradeSecurity`; `TradeSummary` →
`countOfBuys countOfSells amountOfBuys amountOfSells`; `Cash` → `amount
cashSecurity`; `Position` → `quantity positionSecurity`). Live activity showed
`TradeSummary` ("Morning Trading") and `Cash` ("Deposit of $500.00 completed.")
entries. `variant_label()` renders an unknown eighth variant under its raw name.

### Dividends: the typed read (live, 2026-09-23)

A cash entry has no typed kind of its own. Schema-verified fields of
`InvestActivityCashEntry`: `id key date title description
activityDescriptionLink account isRelatedToSecurity cashSecurity amount
tooltipCopy transferDetails`. Unfiltered activity mixes dividends with
securities-lending interest and deposits, all as `Cash` entries told apart
only by their `title`.

The typed route is the connection's own argument:
`activity(first, after, filter: InvestActivityEntryFilterInput, sort,
neverSummarizeTrades)`. The filter's fields are `fromDate`, `toDate`,
`symbols`, and five booleans: `includeCategoryTrading`, `includeCategoryCash`,
`includeCategoryPosition`, `includeCategoryDividend`,
`includeCategoryTransfer`. Observed live:

| Probe | Result |
| --- | --- |
| `includeCategoryDividend: true` alone | Dividend entries only. The other categories are excluded without setting them `false`. |
| Dividend entry shape | `InvestActivityCashEntry`, `title` "Dividend", `description` empty string, `amount` a positive `Float`, symbol under `cashSecurity.symbol`. |
| `fromDate`/`toDate` | ISO dates. Inclusive at both ends: a one-day window on the payment date returns that day's rows, and the day before returns none. |
| `date` | A UTC timestamp at midnight Eastern (`…T04:00:00.000Z` in summer), so the first 10 characters are the local payment date. |
| Entry `id` | Base64 of `InvestActivityCashEntry:{"accountId":…,"activityEntryId":…,"isCredit":…}`. `dividends list` emits the decoded `activityEntryId`. |
| Other cash titles | "Security Lending Interest" (description "Securities lending interest of $… received."), "Cash account transfer", deposits. These are not dividends and the filter excludes them. |
| `includeCategoryCash: true` | Returns the non-dividend cash entries (securities-lending interest, transfers); dividends are their own category. |

The FDX ledger (`transactions list`) also types dividends (`transactionType`
DIVIDEND, observed live), but `transactions list` pages the whole ledger and
filters client-side, so the activity filter is the cheaper read.

### Positions across accounts

`holdings list` needs an account: with none selected it used to exit 2 ("no
account selected"). That was the "usage error" a household capture hit on its
first probe; `-a <ID>` always worked. Now `holdings list` with nothing selected
reads every account and stamps each row with its account, and `positions list`
emits the family `position-list/v1` shape (`symbol`, `quantity`,
`market_value`, `cost_basis`, `average_price`, `unrealized_gain`, `name`,
`cusip`, plus the account fields).

A position node `id` is base64 of `Position:{"accountId":…,"cusip":…}`.
`positions list` emits the decoded `cusip`, never the blob.

`Account.isRetirement` (`Boolean`) is M1's own flag. Live: `true` on the
ROTH_IRA and TRADITIONAL_IRA accounts, `false` on INDIVIDUAL and JOINT. The
`AccountRegistrationEnum` members are INDIVIDUAL, CRYPTO, JOINT, CUSTODIAL,
PARTNERSHIP, LLC, CORPORATION, TRUST, TRADITIONAL_IRA, ROTH_IRA, SEP_IRA,
OTHER (re-read by unauthenticated introspection 2026-10-27; there is **no
rollover or SIMPLE member** — a rollover IRA is a TRADITIONAL_IRA). Every
cross-account row carries `registration` and `is_retirement`; deciding which
dividends are taxable is the consumer's job.

Every cross-account row (and every `accounts list` item) also carries
`account_type`, the family spelling of the registration
(`accounts::family_type`), so a consumer reads M1's and robinhood-cli's IRAs
with one vocabulary:

| Registration | `account_type` |
| --- | --- |
| TRADITIONAL_IRA | `ira_traditional` (rollover IRAs included) |
| ROTH_IRA | `ira_roth` |
| SEP_IRA | `ira_sep` |
| INDIVIDUAL / JOINT | `individual` / `joint` |
| CUSTODIAL, TRUST, CRYPTO, PARTNERSHIP, LLC, CORPORATION | the lowercase name |
| OTHER | `other` |
| a member added later | omitted — `registration` still carries it |

### Net worth by account

`viewer.overview.balances.accountTotals` is per product line only, so M1's
"Invest" figure lumps every investment account together — a taxable account,
a Roth IRA and a rollover IRA in one number. `net-worth` keeps M1's headline
figures and the other product lines, and replaces the Invest row with one row
per account from `AccountsPage`: `account_id`, `name`, `type` (the family
spelling above), `registration`, `is_retirement`, `product: "Invest"`, and
`total` (`balance.totalValue.value`; omitted when `hasValue` is false). A
closed or rejected account holding nothing is left out. The accounts' values
are summed in integer cents against M1's Invest figure; any difference is its
own row (`type: "Invest"`, `product: "Invest"`, `name: "Invest (not matched
to an account)"`, `total`, and no `account_id`) with a note on stderr, so the
rows always sum to what the product lines did. Every product-line row also
carries `product`.

When the split lists an account without a `total` (M1 cannot price it), the
remainder row is emitted even when it is exactly `0.00`, with no stderr note.
It is the only figure that bounds what the unpriced accounts hold, so its
presence separates "they hold nothing" (`0.00`) from "no remainder was
computed". When every listed account is priced, the row appears only when the
remainder is non-zero. A closed or rejected account left out of the split does
not count as unpriced. The human table renders the same rows as `--json`.

Whether the accounts sum to the Invest figure to the cent on a live login is
not yet observed (the session was blocked by Trap 7 before this shipped); the
remainder row is what makes the answer safe either way.

### Documents require a full argument set

Introspection marks `documentType`, `startDate`, `endDate` as nullable, but the
**resolver rejects any request missing one** ("Document Connection is missing
required arguments"). There is no "all types" enum member, so an unfiltered
`documents list` issues **five requests**, one per `DocumentTypeFilterEnumType`
member (STATEMENT, TAX_FORM, TRADE_CONFIRMATION, INVESTMENTS_RELATED,
ACCOUNT_DOCUMENT), and merges. `--type` narrows to one.

### Tax lots

`Account.taxLots` → `AccountTaxLotsConnection { totalCount, pageInfo, edges }`.
`AccountTaxLot` fields (all schema-verified): `id symbol cusip acquisitionDate
quantity costBasis shortLongTermHolding closeDate shortTermRealizedGainLoss
longTermRealizedGainLoss unrealizedGainLoss washSaleIndicator
disallowedWashSaleAmount`. Note `washSaleIndicator` (not the guessed
`isWashSale`), and realized gain **split by term**. **`lotType` is required
(`LotTypeEnum!`)** — verified live, the resolver rejects a nullable variable —
with exactly two members, `OPEN` and `CLOSED`, so `lots list` queries both and
merges (or one, with `--open`/`--closed`).

### Pagination

Every connection carries `pageInfo { hasNextPage endCursor }`. `accounts`,
`positions`, and `taxLots` also carry a `total`/`totalCount`; `positions` and
`taxLots` carry a per-edge `cursor`. Each command owns its loop, capped at 20
pages, and `parse::nodes` accepts `edges[].node`, `nodes[]`, and plain arrays
interchangeably. A `node(id:)` lookup that returns `null` is a **not-found**
(bad `--account`), reported as exit 4 by `parse::require_node`, not as a shape
change.

---

## Tax documents

The reason this CLI exists. **This household opened its first M1 taxable account
in 2026**, so the first consolidated 1099 is for TY2026, delivered early 2027.
But live capture revealed a **deep back-catalog already present**: consolidated
1099s for the Individual account for 2023–2025, plus 1099-R / 5498 / 1099-INT
forms back to **2020**, and monthly statements back to 2024. `documents list
--type tax-form` returned 16 tax forms; `documents download` of the TY2025
consolidated 1099 produced a **valid 17-page `%PDF-1.4`, 66,305 bytes**.

M1's published availability timing (labeled AI-generated by M1, so advisory):
consolidated 1099 by Feb 15 (Mar 15 if reclassified), 1099-R / standalone
1099-INT by Jan 31, 1099-DA by Feb 17, 5498 by May 31.

**Retention: M1 self-serve holds only the last ~3 years of statements** (tax
forms appear to go back further). An argument for `documents download --all`
annually.

### The 2023 clearing-firm gap

M1 moved taxable individual/joint accounts from **Apex Clearing to
self-clearing over July–October 2023**; tax lots closed *before* that live at
Apex, not in M1's data. Confirmed indirectly live: pre-2023 documents are still
served from `edocuments.apexclearing.com`, post-2023 from GCS.

### Other export routes, for context

- **TurboTax import** via account number + 1099 document ID.
- **Plaid** supports M1 (credentials-based, no OAuth) — a fallback if this path
  breaks.
- Realized gains / tax lots are also downloadable as **CSV** from the web UI.

---

## What is still unverified

Short, and none of it blocks the tool:

| Item | Why still open |
| --- | --- |
| Rate limits / lockout | No limits hit in this session; `USER_ACCOUNT_LOCKED` exists but was not (and should not be) triggered. |
| `x-*` header necessity | Reads worked with them; their *absence* was not tested against Cloudflare. |
| Auth0 session end to end | Read from the bundle and the tenant's public metadata, not exercised: no owner session has been captured since Trap 7. The first `auth login --browser` (or `--browser-session`) confirms that `lens.m1.com` takes the Auth0 bearer outside the browser (the bundle says it does). |
| The browser capture live | `auth login --browser` is tested offline only: the expression against the reader's prefix and audience, the host rule, the fixture through the reader. Whether the dashboard's own entry answers the expression the way the synthetic fixture does is confirmed by the owner's first run. |
| Auth0 token lifetime and rotation | The access token's lifetime and whether the tenant rotates refresh tokens are unobserved; `m1f` keeps a rotated token when one comes back and the old one when none does. |
| Auth0 refresh outside a browser | The token endpoint advertises `none` auth for public clients; whether Cloudflare or Auth0's origin rules let a non-browser renewal through is unobserved. A refusal is exit 3 naming the recapture; an HTML answer exit 5. |
| Net worth by account | Whether the accounts sum to M1's Invest figure to the cent is unobserved; a difference becomes its own row, and so does a `0.00` remainder beside an unpriced account. |
| `code` (TOTP) vs `emailCode` | Only the email-MFA path (`EMAIL_AMFA_REQUIRED` → `emailCode`) was exercised live. |

---

## Owner login checklist (browser session, since 2026-10-27)

1. **Probe unauthenticated** — `m1f status`. `NORMAL` means the endpoint is up;
   it says nothing about the password login (Trap 7).
2. **Capture** — `m1f auth login --browser` (add `--overwrite` to replace a
   stored session): sign in in the Chrome window it opens; it closes itself
   once the session is read. Without Chrome, the four steps in `m1f auth
   login --help`: private window at dashboard.m1.com, the DevTools snippet,
   `pbpaste | m1f auth login --browser-session --stdin`, close the window
   without signing out.
3. **Reads** — `m1f accounts list`, `m1f positions list`, `m1f net-worth`.
   `m1f auth status` shows `method: browser-session` and the expiry.
4. **Afterwards** — reads renew the session on their own. When a renewal is
   refused (`invalid_grant`, exit 3), capture again (step 2, with
   `--overwrite`).

## Owner first-login checklist (as actually run, 2026-08-13 — password login, now blocked)

1. **Probe unauthenticated** — `m1f status` (or `m1f api query '{ __typename }'`).
   Live: `NORMAL`. HTML back would mean a Cloudflare challenge.
2. **Set identity** — `m1f config set username you@example.com`.
3. **Log in once** — `m1f auth login` (prompt / `--stdin` / `--from-env`). If M1
   emails a code, `m1f auth login --code <CODE>` replays the whole mutation with
   `emailCode` (it asks for the password again — by design). Live: MFA fired
   (`EMAIL_AMFA_REQUIRED`), code accepted, `expiresIn` 24 h.
4. **Reads** — `m1f accounts list`, then `-a <ID> holdings list` / `activity
   list` / `lots list`.
5. **Documents** — `m1f documents list [--type tax-form]`, then
   `m1f documents download <ID> -o ~/tax/…/` or `--all`.

---

## Sources

Schema and behavior are now first-hand (live introspection + live commands,
2026-08-13). The Auth0 configuration is first-hand too, read from M1's own
public web bundle (`https://dashboard.m1.com/assets/index-*.js`, its
`window.config` in the page) and `https://account.m1.com/.well-known/openid-configuration`
on 2026-10-27. Background, unchanged:

- M1 help center consolidated-1099 / retention articles (labeled AI-generated).
- M1 SEC Rule 17a-5 filings and AWS case study — Apex → self-clearing dating.
- Plaid / Finicity institution support — credentials-based, no OAuth.
