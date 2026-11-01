# Test fixtures — M1 GraphQL response shapes

## Provenance: SYNTHETIC, but now modeled on LIVE-VERIFIED shapes

**No file here was captured from a live M1 account.** Every one is authored by
hand. What changed on **2026-08-13**: the shapes are no longer guesses. M1's
`lens.m1.com/graphql` answers introspection **without authentication**, so the
full schema was pulled and every field name, argument, scalar type, and enum
member below was confirmed against it — and the read/auth/error shapes were then
confirmed a second time by running the real commands against a live account.
The *values* remain fabricated dummies; the *shapes* are real.

| Fixture | Shape confidence | Basis |
| --- | --- | --- |
| `auth/authenticate-*.json` | **HIGH** | `authenticate { didSucceed, error, expiresIn, outcome { accessToken, refreshToken } }`. `error` is an `AuthenticateErrorEnum` (schema-verified); a wrong password returns `INCORRECT_CREDENTIALS` and the email-MFA demand returns `EMAIL_AMFA_REQUIRED` — both observed live. |
| `auth/authenticate-mfa.json` | **HIGH** | The MFA demand is `didSucceed: false` + `error: "EMAIL_AMFA_REQUIRED"`, identical in shape to a credential failure. Confirmed live. |
| `auth/auth0-spa-cache.json` | **MEDIUM** | The value auth0-spa-js stores in the dashboard's localStorage under `@@auth0spajs@@::<clientId>::<audience>::<scope>`: `{ body: { access_token, refresh_token, expires_in, audience, client_id, scope, … }, expiresAt }`. The SDK and its options (`cacheLocation: localstorage`, `useRefreshTokens: true`, the audience, the public client id) were read from M1's public bundle on 2026-10-27; the entry's shape is auth0-spa-js's own. Not yet seen from a live M1 login (docs/api.md, Trap 7). It is also the string `auth login --browser`'s capture expression returns, so the browser route is tested by feeding it through the same reader. The audience is the one URL-shaped value the scrubbing test allows, because it identifies an API rather than locating a resource. |
| `reads/viewer-is-authenticated.json` | **HIGH** | `viewer { isAuthenticated }` — the browser-session login's check. Observed 2026-10-27 answering `false` with no error for a missing or bogus bearer; `true` is what an accepted session reads. |
| `errors/unauthenticated.json` | **MEDIUM** | Kept in the conventional Apollo shape (`extensions.code`) to exercise that fallback branch of the classifier. |
| `errors/validation-failed.json` | **HIGH** | M1's **real** envelope, observed live: the code sits at the **top level** of the error object (not under `extensions`), alongside an `isAuthError` boolean and an `http.status`. |
| `reads/accounts.json` | **HIGH** | `AccountsPage`. The connection **does** carry `pageInfo` (the research had guessed it didn't). Money lives under `balance` — `totalValue { value hasValue }` and `cash { available }`, all `Float`. `isRetirement` (live-verified 2026-09-23) is true exactly on the IRA registrations. |
| `reads/holdings.json` | **HIGH** | Positions hang off `balance.investments.positions`, not off the account node. `cost`, `value`, `unrealizedGain` are wrapper objects of `Float`s. |
| `reads/activity.json` | **HIGH** | `investActivity.activity`. `InvestActivityEntry` is an **interface with 7 implementations**; `id date title description` are interface fields, per-variant fields (`sharePrice`, `tradeSecurity`, `countOfBuys`, …) confirmed from the schema. |
| `reads/dividends.json` | **HIGH** | `investActivity.activity(filter: { includeCategoryDividend: true })`. Every entry is an `InvestActivityCashEntry` titled "Dividend" with an empty `description`, a `Float` amount, and the symbol under `cashSecurity`. Live-verified 2026-09-23; values are dummies and the real relay-blob `id` is replaced by an `act-` dummy. |
| `reads/documents.json` | **HIGH** | `Document` interface fields `id date type name accountName`. The guessed `title`/`category`/`fileName`/`url` do not exist. `url` is deliberately absent — see below. |
| `reads/lots.json` | **HIGH** | `AccountTaxLots`. Field spellings are live-verified: `washSaleIndicator` (not `isWashSale`), split `shortTermRealizedGainLoss` / `longTermRealizedGainLoss`, `disallowedWashSaleAmount`. |
| `reads/net-worth.json` | **HIGH** | `viewer.overview.balances` (`BalancesOverview`): `total`, `assets`/`liabilities` (`NetWorthLabel`), `assetRatio`, `accountTotals[{type,total}]`. Live-verified 2026-08-18. Product lines only: `net-worth` splits the Invest line by account from `reads/accounts.json`'s nodes. |
| `reads/transfers.json` | **HIGH** | `viewer.transfers.pastInstances`. `status` is an object with a `code`, not a scalar. Live-verified 2026-08-18. |
| `reads/transactions.json` | **HIGH** | `Account.fdxTransactions` (FDX ledger). `transactionType` is aliased per variant (`investmentType` / `depositType`) because the enums conflict. Live-verified 2026-08-18. |
| `reads/ira.json` | **HIGH** | `Account.iraContributionTotals.totalsByYear` + `iraContributionLimits.currentYearLimit`. Includes a fractional contribution so the exact-cents remaining math is exercised. Live-verified 2026-08-18. |
| `reads/summary.json` | **HIGH** | `Account.balance.investments.{totalCost,totalValue,totalUnrealizedGain}` + `fundingTotals.totalsByYear`. Live-verified 2026-08-18. |

`docs/api.md` carries the same distinction and its UNVERIFIED-LIVE table is now
empty. When a shape changes upstream, update the fixture, the contract test, and
`docs/api.md` in the same commit.

## Two live findings encoded here, because they bite

- **The document node `id` is a credential.** In reality it is base64 of
  `InvestAccountDocument:{"document":{…}}` whose payload embeds the account
  number and a pre-signed download URL. The fixtures use `doc-#########`
  dummies instead, and no fixture carries a `url` field — because the real
  listing shouldn't be trusted to either, and `documents.rs` decodes the blob
  to the stable inner id and keeps the URL out of band.
- **No pre-signed URL, ever.** A real one is a live credential with a real
  expiry window. `.gitignore` also excludes `*.har` and `captures/`.

## Scrubbing policy

Every file obeys the policy that would apply to a real capture, so the rules
stay exercised and a future real capture can't be dropped in unscrubbed:

- **Tokens** are `DUMMY.ACCESS.TOKEN` / `DUMMY.REFRESH.TOKEN` — never a real
  JWT, not even an expired one.
- **Ids** match `<prefix>-#########` (`acct-`, `hold-`, `act-`, `doc-`).
- **Cursors** match `DUMMYCURSOR###`.
- **CUSIPs** are the obvious dummy `00000DUMMY`.
- **URLs**, if any ever appear, must be on `example.invalid`, a reserved TLD
  that cannot resolve.
- **No email addresses**, no real names, no account numbers.
- Monetary values are obviously fabricated round-ish numbers.

`tests/fixture_shapes.rs::fixtures_obey_the_scrubbing_policy` enforces this
**positively** — every identity-bearing value must match a known dummy shape —
rather than as a denylist, which would have to contain the very strings it
exists to keep out.

## Never commit a raw capture

Scrub into these files by hand. Raw captures carry bearer tokens, session
cookies, `__cf_bm` Cloudflare tokens, and pre-signed URLs.
