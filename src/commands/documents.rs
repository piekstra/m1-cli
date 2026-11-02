//! `m1f documents` — statements, trade confirmations, and tax forms
//! (the `documents/v1` profile).
//!
//! Two rules here were learned live (2026-08-13), not from the schema:
//!
//! 1. **The connection requires `documentType`, `startDate`, AND `endDate`**,
//!    even though introspection marks all three nullable. Omit any one and the
//!    resolver answers "Document Connection is missing required arguments."
//!    There is no "all types" enum member, so an unfiltered list means five
//!    requests, one per `DocumentTypeFilterEnumType` member.
//!
//! 2. **The node `id` is itself a credential.** It is base64 of
//!    `InvestAccountDocument:{"document":{…}}` whose payload embeds the
//!    account number and a pre-signed download URL (~15-minute expiry). It is
//!    also *unstable* — every listing mints a fresh signature, so the blob
//!    changes run to run. The DTO therefore carries the **inner document id**,
//!    which is stable, credential-free, and what `documents download <ID>`
//!    matches on; the raw blob never leaves the process.

use std::io::Write;
use std::path::{Path, PathBuf};

use pk_cli_core::{CliError, Paged, RangeArgs};
use pk_cli_documents::{Document, DownloadBatch, SavedDocument};
use serde_json::{json, Value};

use super::{note_empty, Ctx};
use crate::{graphql, parse};

const MAX_PAGES: usize = 20;
const PAGE_SIZE: u32 = 100;

/// The date window sent when `--since`/`--until` are absent: wide enough to
/// cover everything M1 self-serve retains (observed live: tax forms back to
/// 2020, statements ~3 years).
const EARLIEST: &str = "2000-01-01";

/// `DocumentTypeFilterEnumType`, complete (schema-verified).
const DOC_TYPES: [&str; 5] = [
    "STATEMENT",
    "TAX_FORM",
    "TRADE_CONFIRMATION",
    "INVESTMENTS_RELATED",
    "ACCOUNT_DOCUMENT",
];

#[derive(clap::Args, Debug)]
pub struct ListArgs {
    /// Only one document class: statement, tax-form, trade-confirmation,
    /// investments-related, or account-document.
    #[arg(long = "type", value_name = "TYPE")]
    pub doc_type: Option<String>,

    #[command(flatten)]
    pub range: RangeArgs,
}

/// Map the friendly flag spelling onto the enum member.
pub(crate) fn type_filter(flag: Option<&str>) -> Result<Vec<&'static str>, CliError> {
    let Some(flag) = flag else {
        return Ok(DOC_TYPES.to_vec());
    };
    let want = flag.to_ascii_uppercase().replace('-', "_");
    DOC_TYPES
        .iter()
        .find(|t| **t == want)
        .map(|t| vec![*t])
        .ok_or_else(|| {
            CliError::Usage(format!(
                "unknown document type `{flag}` (known: statement, tax-form, \
                 trade-confirmation, investments-related, account-document)"
            ))
        })
}

#[derive(clap::Args, Debug)]
pub struct DownloadArgs {
    /// A document id from `documents list`. Omit and pass --all for every one.
    pub id: Option<String>,

    /// Download every document (filter with --since/--until/--limit).
    #[arg(long, conflicts_with = "id")]
    pub all: bool,

    /// Output target: a file path or `-` for stdout (single id), or a
    /// directory (with --all). Defaults to the portal's filename here.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<String>,

    #[command(flatten)]
    pub range: RangeArgs,
}

pub fn list(ctx: &Ctx, args: &ListArgs) -> Result<(), CliError> {
    args.range.validate()?;
    let types = type_filter(args.doc_type.as_deref())?;
    let docs = fetch(ctx, &args.range, &types)?;
    if docs.is_empty() {
        note_empty(ctx, "documents");
    }
    let items: Vec<Document> = docs.into_iter().map(|f| f.doc).collect();
    Paged::new("document", items).emit(ctx.common.json);
    Ok(())
}

pub fn download(ctx: &Ctx, args: &DownloadArgs) -> Result<(), CliError> {
    // Validate the argument combination before anything is spent.
    if args.all && args.output.as_deref() == Some("-") {
        return Err(CliError::Usage(
            "--all can't stream to stdout; give a directory with -o, or omit it".into(),
        ));
    }
    match (args.all, args.id.as_deref()) {
        (true, _) => download_all(ctx, args),
        (false, Some(id)) => download_one(ctx, id, args),
        (false, None) => Err(CliError::Usage(
            "give a document id (see `m1f documents list`) or --all".into(),
        )),
    }
}

fn download_one(ctx: &Ctx, id: &str, args: &DownloadArgs) -> Result<(), CliError> {
    let docs = fetch(ctx, &RangeArgs::default(), &DOC_TYPES)?;
    let fetched = docs
        .into_iter()
        .find(|f| f.doc.id == id)
        .ok_or_else(|| CliError::NotFound(format!("no document with id `{id}`")))?;
    let url = signed_url(ctx, &fetched)?;

    let bytes = fetch_document(ctx, &url)?;
    let doc = fetched.doc;
    let file_name = doc.file.clone().unwrap_or_else(|| format!("{id}.pdf"));

    // `-o -` makes the file itself the stdout data stream; diagnostics go to
    // stderr so a pipe stays clean.
    if args.output.as_deref() == Some("-") {
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| CliError::Upstream(format!("writing document to stdout: {e}")))?;
        if !ctx.common.quiet {
            eprintln!("wrote {} bytes ({}) to stdout", bytes.len(), doc.name);
        }
        return Ok(());
    }

    let path = resolve_output(args.output.as_deref(), &file_name);
    write_file(&path, &bytes)?;
    let saved = SavedDocument::from_document(&doc, path.display().to_string(), bytes.len() as u64);
    pk_cli_documents::emit(&saved, ctx.common.json);
    Ok(())
}

fn download_all(ctx: &Ctx, args: &DownloadArgs) -> Result<(), CliError> {
    args.range.validate()?;
    let docs = fetch(ctx, &args.range, &DOC_TYPES)?;

    let dir = args
        .output
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or_default();
    if !dir.as_os_str().is_empty() && !dir.exists() {
        std::fs::create_dir_all(&dir)
            .map_err(|e| CliError::Upstream(format!("creating {}: {e}", dir.display())))?;
    }

    let mut saved = Vec::new();
    for fetched in docs {
        let bytes = match signed_url(ctx, &fetched).and_then(|url| fetch_document(ctx, &url)) {
            Ok(b) => b,
            Err(e) => {
                // One undownloadable document must not abort a whole-year
                // archive run; report it and keep going.
                if !ctx.common.quiet {
                    eprintln!("skipping `{}`: {e}", fetched.doc.id);
                }
                continue;
            }
        };
        let doc = fetched.doc;
        let file_name = doc
            .file
            .clone()
            .unwrap_or_else(|| format!("{}.pdf", doc.id));
        let path = dir.join(&file_name);
        write_file(&path, &bytes)?;
        saved.push(SavedDocument::from_document(
            &doc,
            path.display().to_string(),
            bytes.len() as u64,
        ));
    }

    if saved.is_empty() {
        note_empty(ctx, "downloadable documents");
    }
    let batch = DownloadBatch::new(dir.display().to_string(), saved);
    pk_cli_documents::emit(&batch, ctx.common.json);
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    std::fs::write(path, bytes)
        .map_err(|e| CliError::Upstream(format!("writing {}: {e}", path.display())))
}

/// Where a single download lands: an explicit file path, a directory (the
/// portal's own filename inside it), or the current directory.
fn resolve_output(output: Option<&str>, file_name: &str) -> PathBuf {
    match output {
        None => PathBuf::from(file_name),
        Some(o) => {
            let p = PathBuf::from(o);
            if p.is_dir() || o.ends_with('/') {
                p.join(file_name)
            } else {
                p
            }
        }
    }
}

/// A listed document with the two provider artifacts that must never reach
/// output: the raw Relay id blob (embeds the account number and a signed URL)
/// and the embedded pre-signed URL itself.
pub struct Fetched {
    pub doc: Document,
    /// The raw node id, exactly as M1 sent it — what
    /// `CreateAccountDocumentLink` expects as `accountDocumentId`.
    raw_id: String,
    /// The pre-signed URL embedded in the id blob. Fresh as of the listing
    /// (observed expiry: 900 s), so a download that follows immediately can
    /// use it without minting a new link.
    embedded_url: Option<String>,
}

impl Fetched {
    /// The document as the MCP tools may show it. When the id blob does not
    /// decode, [`document_of`] falls back to the raw blob for `id` (and for
    /// the name, when M1 sent none); a raw id that is long or relay-shaped
    /// can then carry the account number and a signed URL, so it is blanked
    /// rather than shown.
    pub(crate) fn listed(self) -> Document {
        let mut doc = self.doc;
        let is_blob = doc.id == self.raw_id
            && (self.raw_id.len() > 64 || parse::decode_relay_blob(&self.raw_id).is_some());
        if is_blob {
            doc.name = doc.name.replace(&self.raw_id, "Untitled document");
            doc.id = String::new();
        }
        doc
    }
}

/// The URL to fetch a document from.
///
/// Verified live (2026-08-13): **`InvestAccountDocument` links come from the
/// listing itself** — every invest node's id blob embeds a URL signed at
/// listing time (`urlGetType: "Provided"`, ~15-minute expiry), and
/// `CreateAccountDocumentLink` *refuses* invest ids with "Unexpected ID type,
/// expected: AccountDocument. Received: InvestAccountDocument". The mutation
/// is the mint for the ACCOUNT_DOCUMENT class only, so it runs only when no
/// embedded URL exists. Downloads always re-fetch the listing first, so the
/// embedded URL is seconds old by the time it is used.
///
/// `CreateAccountDocumentLink` is a GraphQL *mutation*, and it is the only
/// non-auth mutation `m1f` sends. It changes no account state — no money
/// moves, no order is placed, no setting changes; it just returns a
/// short-lived download link. The read-only claim is about account state, and
/// this preserves it. See SECURITY.md.
fn signed_url(ctx: &Ctx, fetched: &Fetched) -> Result<String, CliError> {
    if let Some(url) = &fetched.embedded_url {
        return Ok(url.clone());
    }
    let data = ctx.read(|c| {
        c.execute(
            graphql::CREATE_DOCUMENT_LINK,
            // The input field is `accountDocumentId` (schema-verified; the
            // first guess of `documentId` was refused by validation). It takes
            // the raw Relay id blob, not the inner document id.
            json!({ "input": { "accountDocumentId": fetched.raw_id } }),
            Some("CreateAccountDocumentLink"),
        )
    })?;
    crate::client::check_did_succeed(&data)?;
    parse::opt_string(
        parse::at(&data, &["createAccountDocumentLink", "outcome"])?,
        "url",
    )
    .ok_or_else(|| {
        CliError::Upstream(format!(
            "M1 minted no download link for document `{}` — it may only be \
                 viewable in M1's app",
            fetched.doc.id
        ))
    })
}

/// Download and sanity-check a document's bytes.
///
/// The GET goes to a storage host (GCS for self-clearing docs, Apex's
/// edocuments site for legacy IRA docs), and a stale or refused link can
/// answer with an HTML page and a 200. Writing that to `whatever.pdf` would
/// look like success, so anything that doesn't start like a PDF is an error.
fn fetch_document(ctx: &Ctx, url: &str) -> Result<Vec<u8>, CliError> {
    let bytes = ctx.read(|c| c.download(url))?;
    if bytes.starts_with(b"%PDF") {
        return Ok(bytes);
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(120)]).to_lowercase();
    if head.trim_start().starts_with("<!doctype html") || head.trim_start().starts_with("<html") {
        return Err(CliError::Upstream(
            "the download URL answered with an HTML page, not a document — the link \
             probably expired; re-run the download"
                .into(),
        ));
    }
    // Not a PDF but not obviously HTML either — pass it through, the provider
    // may legitimately serve another format someday.
    Ok(bytes)
}

/// Fetch documents across the requested type filters, following cursors.
///
/// All three of `documentType`, `startDate`, `endDate` are sent on every
/// request because the resolver requires them (live finding — introspection
/// says nullable, the resolver says otherwise).
pub(crate) fn fetch(
    ctx: &Ctx,
    range: &RangeArgs,
    types: &[&str],
) -> Result<Vec<Fetched>, CliError> {
    let page_size = range.limit.map(|n| n.min(PAGE_SIZE)).unwrap_or(PAGE_SIZE);
    let start = range.since.clone().unwrap_or_else(|| EARLIEST.to_string());
    let end = range
        .until
        .clone()
        .unwrap_or_else(|| pk_cli_core::dates::fmt_iso(pk_cli_core::dates::today()));
    let mut out: Vec<Fetched> = Vec::new();

    for doc_type in types {
        let mut cursor: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let vars = json!({
                "first": page_size,
                "after": cursor,
                "documentType": doc_type,
                "startDate": start,
                "endDate": end,
            });
            let data =
                ctx.read(|c| c.execute(graphql::DOCUMENTS, vars.clone(), Some("DocumentList")))?;
            let container = parse::at(&data, &["viewer", "documents"])?.clone();
            for node in parse::nodes(&data, &["viewer", "documents"])? {
                out.push(document_of(&node)?);
            }
            pages += 1;

            let next = parse::next_cursor(&container);
            if next.is_some() && next == cursor {
                break;
            }
            cursor = next;
            if cursor.is_none() || pages >= MAX_PAGES {
                break;
            }
        }
    }

    // Newest first across the merged types, then window + cap.
    out.sort_by(|a, b| b.doc.date.cmp(&a.doc.date));
    let filtered: Vec<Fetched> = out
        .into_iter()
        .filter(|f| in_window(f.doc.date.as_deref(), range))
        .take(range.limit.map(|n| n as usize).unwrap_or(usize::MAX))
        .collect();
    Ok(filtered)
}

fn in_window(date: Option<&str>, range: &RangeArgs) -> bool {
    let after = range
        .since
        .as_deref()
        .zip(date)
        .map(|(s, d)| d >= s)
        .unwrap_or(true);
    let before = range
        .until
        .as_deref()
        .zip(date)
        .map(|(u, d)| d <= u)
        .unwrap_or(true);
    after && before
}

pub(crate) fn document_of(v: &Value) -> Result<Fetched, CliError> {
    let raw_id = parse::id(v, "id")?;
    let inner = decode_id_blob(&raw_id);

    // The DTO id is the *inner* document id: stable across listings and free
    // of the account number and signed URL the raw blob carries. Fall back to
    // the raw blob only if the blob shape ever changes.
    let id = inner
        .as_ref()
        .and_then(|d| parse::opt_string(d, "id"))
        .unwrap_or_else(|| raw_id.clone());

    // The interface field is `name` (schema-verified; there is no `title`).
    // The account label disambiguates identically-named docs across accounts
    // ("July 2026 Brokerage Statement" exists once per account).
    let base_name = parse::opt_string(v, "name")
        .or_else(|| parse::opt_string(v, "title"))
        .unwrap_or_else(|| id.clone());
    // Every label source gets the account-number strip: Apex-era documents
    // carry the full "5QLXXXXX - Invest Roth IRA" descriptor in
    // `accountName.subLabel` too (observed live), not just in the blob.
    let account_label = v
        .get("accountName")
        .and_then(|a| parse::opt_string(a, "subLabel").or_else(|| parse::opt_string(a, "label")))
        .or_else(|| {
            inner
                .as_ref()
                .and_then(|d| parse::opt_string(d, "accountDescription"))
        })
        .map(|desc| strip_account_number(&desc));
    let name = match &account_label {
        Some(label) => format!("{base_name} — {label}"),
        None => base_name,
    };

    let mut doc = Document::new(id, name);
    doc.date = parse::date_at(v, &["date", "createdAt", "periodEnd"]);
    // `type` is a DocumentTypeEnum: STATEMENT, TAX_FORM, TRADE_CONFIRMATION,
    // INVESTMENTS_RELATED, or ACCOUNT_DOCUMENT.
    doc.category = parse::opt_string(v, "type").or_else(|| parse::opt_string(v, "category"));
    // There is no filename field on the schema; derive one from name + date.
    doc.file = Some(file_name_for(&doc));

    let embedded_url = inner
        .as_ref()
        .and_then(|d| parse::opt_string(d, "url"))
        .or_else(|| parse::opt_string(v, "url"));
    Ok(Fetched {
        doc,
        raw_id,
        embedded_url,
    })
}

/// Decode M1's Relay-style document id: base64 of
/// `InvestAccountDocument:{"document":{…}}`. Returns the inner `document`
/// object, or None if the blob isn't shaped that way.
fn decode_id_blob(raw: &str) -> Option<Value> {
    parse::decode_relay_blob(raw)?
        .get("document")
        .cloned()
        .filter(Value::is_object)
}

/// `"1AB23456 - Invest Individual"` → `"Invest Individual"`: keep the human
/// half of M1's account descriptor, drop the account number. Only strips when
/// the prefix actually looks like an account number, so a nickname containing
/// " - " survives intact.
fn strip_account_number(desc: &str) -> String {
    if let Some((prefix, rest)) = desc.split_once(" - ") {
        let looks_like_account = prefix.len() >= 6
            && prefix.chars().all(|c| c.is_ascii_alphanumeric())
            && prefix.chars().any(|c| c.is_ascii_digit());
        if looks_like_account {
            return rest.to_string();
        }
    }
    desc.to_string()
}

/// A filesystem-safe filename for a document that names none: date + slugged
/// name, e.g. `2026-07-31-monthly-statement.pdf`.
fn file_name_for(doc: &Document) -> String {
    let slug: String = doc
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    match &doc.date {
        Some(d) => format!("{d}-{slug}.pdf"),
        None => format!("{slug}.pdf"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A synthetic Relay id blob shaped exactly like M1's (observed live
    /// 2026-08-13): base64 of `InvestAccountDocument:{"document":{…}}`, whose
    /// payload embeds the account number and a pre-signed URL. All values here
    /// are dummies.
    fn blob() -> String {
        let inner = json!({
            "document": {
                "id": "00000000-1111-2222-3333-444444444444",
                "date": "2026-07-31",
                "accountNumber": "1AB23456",
                "accountDescription": "1AB23456 - Invest Individual",
                "documentName": "July 2026 Brokerage Statement",
                "documentType": "STATEMENT",
                "url": "https://storage.example.test/dummy.pdf?X-Sig=SYNTHETIC",
                "urlGetType": "Provided"
            }
        });
        base64_encode_for_tests(format!("InvestAccountDocument:{inner}").as_bytes())
    }

    fn base64_encode_for_tests(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let b = [
                chunk[0],
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
            ];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if chunk.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn document_of_uses_the_inner_id_and_quarantines_the_credential_blob() {
        let v = json!({
            "__typename": "InvestAccountDocument",
            "id": blob(), "name": "July 2026 Brokerage Statement",
            "date": "2026-07-31", "type": "STATEMENT",
            "accountName": { "label": "Fun money", "subLabel": "Invest Individual" }
        });
        let fetched = document_of(&v).unwrap();
        // Stable inner id, not the rotating blob.
        assert_eq!(fetched.doc.id, "00000000-1111-2222-3333-444444444444");
        // Account label disambiguates same-named docs across accounts.
        assert_eq!(
            fetched.doc.name,
            "July 2026 Brokerage Statement — Invest Individual"
        );
        assert_eq!(fetched.doc.category.as_deref(), Some("STATEMENT"));
        assert_eq!(
            fetched.embedded_url.as_deref(),
            Some("https://storage.example.test/dummy.pdf?X-Sig=SYNTHETIC")
        );
        // Neither the signed URL, the account number, nor the raw blob may
        // reach the serialized DTO.
        let dto = serde_json::to_value(&fetched.doc).unwrap().to_string();
        assert!(!dto.contains("X-Sig"), "pre-signed URL leaked into the DTO");
        assert!(
            !dto.contains("1AB23456"),
            "account number leaked into the DTO"
        );
        assert!(
            !dto.contains(&fetched.raw_id),
            "raw id blob leaked into the DTO"
        );
    }

    #[test]
    fn an_undecodable_id_falls_back_to_the_raw_string() {
        let fetched = document_of(&json!({ "id": "d9" })).unwrap();
        assert_eq!(fetched.doc.id, "d9");
        assert_eq!(fetched.doc.name, "d9");
        assert_eq!(fetched.doc.file.as_deref(), Some("d9.pdf"));
        assert!(fetched.embedded_url.is_none());
    }

    #[test]
    fn account_description_strips_the_account_number() {
        assert_eq!(
            strip_account_number("1AB23456 - Invest Individual"),
            "Invest Individual"
        );
        assert_eq!(strip_account_number("no separator"), "no separator");
        // A human nickname with a dash is not an account descriptor.
        assert_eq!(strip_account_number("Fun - money"), "Fun - money");
        // The Apex subLabel shape observed live must strip too.
        let v = json!({
            "id": "d1", "name": "Tax Form 1099R",
            "accountName": { "subLabel": "1AB23456 - Invest Roth IRA" }
        });
        let fetched = document_of(&v).unwrap();
        assert_eq!(fetched.doc.name, "Tax Form 1099R — Invest Roth IRA");
        assert!(!serde_json::to_value(&fetched.doc)
            .unwrap()
            .to_string()
            .contains("1AB23456"));
    }

    #[test]
    fn base64_round_trips_the_blob() {
        let raw = blob();
        let decoded = decode_id_blob(&raw).expect("decodes");
        assert_eq!(decoded["id"], json!("00000000-1111-2222-3333-444444444444"));
        assert_eq!(decoded["documentType"], json!("STATEMENT"));
    }

    #[test]
    fn type_filter_accepts_friendly_spellings_and_rejects_junk() {
        assert_eq!(type_filter(Some("tax-form")).unwrap(), vec!["TAX_FORM"]);
        assert_eq!(type_filter(Some("STATEMENT")).unwrap(), vec!["STATEMENT"]);
        assert_eq!(type_filter(None).unwrap().len(), 5);
        assert_eq!(type_filter(Some("nope")).unwrap_err().exit_code(), 2);
    }

    #[test]
    fn resolve_output_handles_path_dir_and_default() {
        assert_eq!(resolve_output(None, "a.pdf"), PathBuf::from("a.pdf"));
        assert_eq!(
            resolve_output(Some("out.pdf"), "a.pdf"),
            PathBuf::from("out.pdf")
        );
        assert_eq!(
            resolve_output(Some("some/dir/"), "a.pdf"),
            PathBuf::from("some/dir/a.pdf")
        );
    }

    #[test]
    fn in_window_is_inclusive_and_keeps_undated_rows() {
        let r = RangeArgs {
            since: Some("2026-01-01".into()),
            until: Some("2026-12-31".into()),
            limit: None,
        };
        assert!(in_window(Some("2026-01-01"), &r));
        assert!(in_window(Some("2026-12-31"), &r));
        assert!(!in_window(Some("2025-12-31"), &r));
        // An undated document is filtered only by --limit, never by a bound.
        assert!(in_window(None, &r));
    }
}
