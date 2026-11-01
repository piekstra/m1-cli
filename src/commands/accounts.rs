//! `m1f accounts list` — the investment accounts on the login.

use pk_cli_core::{output, CliError, RangeArgs};
use serde_json::{json, Value};

use super::{emit, items, note_empty, paginate, table_view, Ctx};
use crate::{graphql, parse};

const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 50;

pub fn list(ctx: &Ctx, range: &RangeArgs) -> Result<(), CliError> {
    // Validate before the keychain or network is touched.
    range.validate()?;

    let mut rows: Vec<Value> = Vec::new();
    for node in fetch_nodes(ctx)? {
        rows.push(account_dto(&node)?);
    }
    // Accounts carry no date; `paginate` here only applies --limit.
    let rows = paginate(rows, "opened", range);

    if rows.is_empty() {
        note_empty(ctx, "accounts");
    }
    emit(ctx, "account-list", json!({ "items": rows }), |v| {
        output::table(&table_view(
            &items(v, "items"),
            &[
                "id",
                "name",
                "account_type",
                "total_value",
                "cash",
                "status",
            ],
        ));
    });
    Ok(())
}

/// The family's spelling of an M1 registration (`AccountRegistrationEnum`,
/// re-read by unauthenticated introspection 2026-10-27: INDIVIDUAL, CRYPTO,
/// JOINT, CUSTODIAL, PARTNERSHIP, LLC, CORPORATION, TRUST, TRADITIONAL_IRA,
/// ROTH_IRA, SEP_IRA, OTHER).
///
/// The IRA spellings are robinhood-cli's (`ira_traditional`, `ira_roth`), so
/// a consumer reads both brokerages' IRAs with one vocabulary; `ira_sep`
/// follows the same pattern. M1 has no rollover registration: a rollover IRA
/// (a 401(k) moved into an IRA) is registered TRADITIONAL_IRA, so it is
/// `ira_traditional` here. A member this table does not know yields `None`
/// and the field is omitted — the raw `registration` still travels beside
/// it, so a new M1 registration is never silently read as a known type.
pub fn family_type(registration: &str) -> Option<&'static str> {
    Some(match registration {
        "INDIVIDUAL" => "individual",
        "JOINT" => "joint",
        "TRADITIONAL_IRA" => "ira_traditional",
        "ROTH_IRA" => "ira_roth",
        "SEP_IRA" => "ira_sep",
        "CUSTODIAL" => "custodial",
        "TRUST" => "trust",
        "CRYPTO" => "crypto",
        "PARTNERSHIP" => "partnership",
        "LLC" => "llc",
        "CORPORATION" => "corporation",
        "OTHER" => "other",
        _ => return None,
    })
}

/// Every account node on the login, following cursors.
///
/// `AccountConnection` paginates (schema-verified — the research guessed it
/// didn't), so this follows cursors like every other list, with the usual cap.
pub fn fetch_nodes(ctx: &Ctx) -> Result<Vec<Value>, CliError> {
    let mut cursor: Option<String> = None;
    let mut out: Vec<Value> = Vec::new();
    let mut pages = 0usize;
    loop {
        let vars = json!({ "first": PAGE_SIZE, "after": cursor });
        let data =
            ctx.read(|c| c.execute(graphql::ACCOUNTS, vars.clone(), Some("AccountsPage")))?;
        let container = parse::at(&data, &["viewer", "accounts"])?.clone();
        out.extend(parse::nodes(&data, &["viewer", "accounts"])?);
        pages += 1;
        let next = parse::next_cursor(&container);
        if next.is_none() || next == cursor || pages >= MAX_PAGES {
            break;
        }
        cursor = next;
    }
    Ok(out)
}

/// The account facts a cross-account row carries, so a consumer can tell a
/// taxable account's position or dividend from a retirement account's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountRef {
    pub id: String,
    pub name: Option<String>,
    pub registration: Option<String>,
    /// M1's own `Account.isRetirement` flag (live-verified 2026-09-23: true on
    /// the ROTH_IRA and TRADITIONAL_IRA accounts, false on INDIVIDUAL/JOINT).
    /// Required: a consumer excludes IRA dividends from taxable income on it,
    /// so a missing flag is a shape change, not a default.
    pub is_retirement: bool,
}

impl AccountRef {
    pub fn from_node(v: &Value) -> Result<Self, CliError> {
        let id = parse::id(v, "id")?;
        let is_retirement = v
            .get("isRetirement")
            .and_then(Value::as_bool)
            .ok_or_else(|| {
                CliError::Upstream(format!(
                    "account `{id}` carries no boolean `isRetirement` — the account \
                     shape changed; see docs/api.md"
                ))
            })?;
        Ok(AccountRef {
            name: parse::opt_string(v, "nickname").or_else(|| parse::opt_string(v, "name")),
            registration: parse::opt_string(v, "registration"),
            is_retirement,
            id,
        })
    }

    /// The account's type in the family spelling ([`family_type`]).
    pub fn account_type(&self) -> Option<&'static str> {
        self.registration.as_deref().and_then(family_type)
    }

    /// Stamp the account facts onto a row, after its own fields.
    pub fn stamp(&self, row: &mut Value) {
        row["account_id"] = json!(self.id);
        if let Some(name) = &self.name {
            row["account_name"] = json!(name);
        }
        if let Some(kind) = self.account_type() {
            row["account_type"] = json!(kind);
        }
        if let Some(reg) = &self.registration {
            row["registration"] = json!(reg);
        }
        row["is_retirement"] = json!(self.is_retirement);
    }
}

/// An account's total value, or `None` when M1 itself could not price it
/// (`hasValue: false`) — never rendered as $0.00.
///
/// Money lives under `balance` (schema-verified): `totalValue` is a
/// `TotalAccountValue { value hasValue }` wrapper.
pub fn total_value(v: &Value) -> Option<pk_cli_core::Money> {
    let balance = v.get("balance").unwrap_or(v);
    balance.get("totalValue").and_then(|t| {
        if t.get("hasValue") == Some(&Value::Bool(false)) {
            return None;
        }
        parse::money_at(t, "value").or_else(|| parse::money(t))
    })
}

/// Run `fetch` for each account in turn and stamp every row it returns with
/// that account — the shared fan-out of every household read.
pub fn rows_across(
    accounts: &[AccountRef],
    mut fetch: impl FnMut(&AccountRef) -> Result<Vec<Value>, CliError>,
) -> Result<Vec<Value>, CliError> {
    let mut out = Vec::new();
    for acct in accounts {
        for mut row in fetch(acct)? {
            acct.stamp(&mut row);
            out.push(row);
        }
    }
    Ok(out)
}

/// The accounts a household-scope read covers: the one named by `selected`,
/// or every account on the login when nothing is selected.
///
/// A selected id that is not on the login is a not-found (exit 4) rather than
/// a silently empty result.
pub fn scope(ctx: &Ctx, selected: Option<&str>) -> Result<Vec<AccountRef>, CliError> {
    let all = fetch_nodes(ctx)?
        .iter()
        .map(AccountRef::from_node)
        .collect::<Result<Vec<_>, _>>()?;
    narrow(all, selected)
}

fn narrow(all: Vec<AccountRef>, selected: Option<&str>) -> Result<Vec<AccountRef>, CliError> {
    match selected {
        None => Ok(all),
        Some(id) => {
            let hit: Vec<AccountRef> = all.into_iter().filter(|a| a.id == id).collect();
            if hit.is_empty() {
                return Err(CliError::NotFound(format!(
                    "no account `{id}` on this login (see `m1f accounts list`)"
                )));
            }
            Ok(hit)
        }
    }
}

/// One account row. Identifying fields lead, per the output contract.
///
/// Money lives under `balance` (schema-verified): see [`total_value`] for
/// the total, and cash is `cash.available`. `hasValue: false` means M1
/// itself could not price the account, so the column is omitted rather than
/// rendered as $0.00.
fn account_dto(v: &Value) -> Result<Value, CliError> {
    let mut dto = json!({ "id": parse::id(v, "id")? });
    // `nickname` is the owner's own label; prefer it over the product name.
    if let Some(name) = parse::opt_string(v, "nickname").or_else(|| parse::opt_string(v, "name")) {
        dto["name"] = json!(name);
    }
    if let Some(reg) = parse::opt_string(v, "registration") {
        if let Some(kind) = family_type(&reg) {
            dto["account_type"] = json!(kind);
        }
        dto["registration"] = json!(reg);
    }
    let balance = v.get("balance").unwrap_or(v);
    if let Some(total) = total_value(v) {
        dto["total_value"] = serde_json::to_value(total).unwrap_or(Value::Null);
    }
    if let Some(cash) = balance
        .get("cash")
        .and_then(|c| parse::money_at(c, "available"))
    {
        dto["cash"] = serde_json::to_value(cash).unwrap_or(Value::Null);
    }
    if let Some(status) = parse::opt_string(v, "status") {
        dto["status"] = json!(status);
    }
    if let Some(ret) = v.get("isRetirement").and_then(Value::as_bool) {
        dto["is_retirement"] = json!(ret);
    }
    Ok(dto)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn account_dto_leads_with_the_identifier() {
        let v = json!({
            "id": "acct-1", "name": "Individual", "registration": "INDIVIDUAL",
            "status": "OPENED",
            "balance": {
                "totalValue": { "value": 1234.5, "hasValue": true },
                "cash": { "available": 10 }
            }
        });
        let dto = account_dto(&v).unwrap();
        let keys: Vec<&str> = dto
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys[0], "id");
        assert_eq!(dto["total_value"]["amount"], json!("1234.50"));
        assert_eq!(dto["cash"]["amount"], json!("10.00"));
        assert_eq!(dto["total_value"]["currency"], json!("USD"));
    }

    #[test]
    fn a_nickname_wins_over_the_product_name() {
        let v = json!({ "id": "a", "name": "Individual", "nickname": "Taxable" });
        assert_eq!(account_dto(&v).unwrap()["name"], json!("Taxable"));
    }

    #[test]
    fn an_unpriced_account_omits_total_rather_than_rendering_zero() {
        let v = json!({
            "id": "a",
            "balance": { "totalValue": { "value": 0.0, "hasValue": false } }
        });
        assert!(account_dto(&v).unwrap().get("total_value").is_none());
    }

    #[test]
    fn the_retirement_flag_passes_through() {
        let v = json!({ "id": "a", "registration": "ROTH_IRA", "isRetirement": true });
        assert_eq!(account_dto(&v).unwrap()["is_retirement"], json!(true));
    }

    fn acct(id: &str) -> AccountRef {
        AccountRef {
            id: id.into(),
            name: None,
            registration: None,
            is_retirement: false,
        }
    }

    #[test]
    fn an_account_without_the_retirement_flag_fails_loudly() {
        let err = AccountRef::from_node(&json!({ "id": "a" })).unwrap_err();
        assert_eq!(err.exit_code(), 5);
        let err = AccountRef::from_node(&json!({ "id": "a", "isRetirement": null })).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn an_account_ref_reads_the_node() {
        let a = AccountRef::from_node(&json!({
            "id": "a", "name": "Roth IRA", "registration": "ROTH_IRA", "isRetirement": true
        }))
        .unwrap();
        assert!(a.is_retirement);
        assert_eq!(a.registration.as_deref(), Some("ROTH_IRA"));
    }

    #[test]
    fn rows_across_stamps_each_row_with_its_own_account() {
        let accts = vec![acct("a"), acct("b")];
        let rows = rows_across(&accts, |a| Ok(vec![json!({ "n": a.id.clone() })])).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["account_id"], json!("a"));
        assert_eq!(rows[1]["account_id"], json!("b"));
        assert_eq!(rows[1]["is_retirement"], json!(false));
    }

    #[test]
    fn rows_across_propagates_a_fetch_failure() {
        let accts = vec![acct("a")];
        let err = rows_across(&accts, |_| Err(CliError::Upstream("x".into()))).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn no_selection_keeps_every_account() {
        assert_eq!(narrow(vec![acct("a"), acct("b")], None).unwrap().len(), 2);
    }

    #[test]
    fn a_selection_narrows_to_that_account() {
        let got = narrow(vec![acct("a"), acct("b")], Some("b")).unwrap();
        assert_eq!(got, vec![acct("b")]);
    }

    #[test]
    fn an_unknown_selection_is_not_found() {
        let err = narrow(vec![acct("a")], Some("zzz")).unwrap_err();
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn stamp_adds_the_account_facts_after_the_row_fields() {
        let a = AccountRef {
            id: "acct-1".into(),
            name: Some("Roth".into()),
            registration: Some("ROTH_IRA".into()),
            is_retirement: true,
        };
        let mut row = json!({ "symbol": "VTI" });
        a.stamp(&mut row);
        let keys: Vec<&str> = row
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            [
                "symbol",
                "account_id",
                "account_name",
                "account_type",
                "registration",
                "is_retirement"
            ]
        );
        assert_eq!(row["account_type"], json!("ira_roth"));
    }

    #[test]
    fn every_registration_maps_to_the_family_spelling() {
        for (reg, kind) in [
            ("INDIVIDUAL", "individual"),
            ("JOINT", "joint"),
            ("TRADITIONAL_IRA", "ira_traditional"),
            ("ROTH_IRA", "ira_roth"),
            ("SEP_IRA", "ira_sep"),
            ("CUSTODIAL", "custodial"),
            ("TRUST", "trust"),
            ("CRYPTO", "crypto"),
            ("PARTNERSHIP", "partnership"),
            ("LLC", "llc"),
            ("CORPORATION", "corporation"),
            ("OTHER", "other"),
        ] {
            assert_eq!(family_type(reg), Some(kind), "{reg}");
        }
    }

    #[test]
    fn an_unknown_registration_has_no_family_type_and_is_not_stamped_with_one() {
        assert_eq!(family_type("SIMPLE_IRA"), None);
        assert_eq!(family_type("traditional_ira"), None);
        let a = AccountRef {
            id: "acct-1".into(),
            name: None,
            registration: Some("SOMETHING_NEW".into()),
            is_retirement: true,
        };
        let mut row = json!({});
        a.stamp(&mut row);
        assert!(row.get("account_type").is_none());
        assert_eq!(row["registration"], json!("SOMETHING_NEW"));
    }

    #[test]
    fn an_account_row_carries_its_family_type_before_the_registration() {
        let dto = account_dto(&json!({
            "id": "a", "name": "Rollover IRA", "registration": "TRADITIONAL_IRA"
        }))
        .unwrap();
        assert_eq!(dto["account_type"], json!("ira_traditional"));
        let keys: Vec<&str> = dto
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["id", "name", "account_type", "registration"]);
    }

    #[test]
    fn a_numeric_id_is_accepted() {
        let dto = account_dto(&json!({ "id": 42 })).unwrap();
        assert_eq!(dto["id"], json!("42"));
    }

    #[test]
    fn a_missing_id_is_a_loud_failure_not_a_blank_row() {
        let err = account_dto(&json!({ "name": "x" })).unwrap_err();
        assert_eq!(err.exit_code(), 5);
    }

    #[test]
    fn absent_optional_fields_are_omitted_rather_than_null() {
        let dto = account_dto(&json!({ "id": "a" })).unwrap();
        assert!(dto.get("name").is_none());
        assert!(dto.get("total_value").is_none());
    }
}
