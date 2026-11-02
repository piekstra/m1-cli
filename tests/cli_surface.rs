//! Black-box tests over the built binary.
//!
//! Every test here is **offline and credential-free**: nothing may touch the
//! network or the OS keychain. That is not just hygiene — M1's login can spend
//! an MFA code and is rate-limited, and CI has no keychain at all. So these
//! exercise argument validation, help rendering, and the error contract, all of
//! which must happen *before* the CLI reaches for a credential.

use assert_cmd::Command;
use predicates::prelude::*;

fn m1f() -> Command {
    let mut c = Command::cargo_bin("m1f").expect("binary builds");
    // Don't let a developer's real environment leak into a test run.
    c.env_remove("M1F_ACCOUNT")
        .env_remove("M1F_BASE_URL")
        .env_remove("NO_COLOR");
    c
}

#[test]
fn help_lists_the_standard_surface() {
    m1f()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("auth"))
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("accounts"))
        .stdout(predicate::str::contains("holdings"))
        .stdout(predicate::str::contains("activity"))
        .stdout(predicate::str::contains("documents"))
        .stdout(predicate::str::contains("lots"))
        .stdout(predicate::str::contains("transactions"))
        .stdout(predicate::str::contains("transfers"))
        .stdout(predicate::str::contains("net-worth"))
        .stdout(predicate::str::contains("ira"))
        .stdout(predicate::str::contains("summary"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("api"))
        .stdout(predicate::str::contains("mcp"))
        .stdout(predicate::str::contains("self-update"))
        .stdout(predicate::str::contains("completions"))
        .stdout(predicate::str::contains("info"));
}

/// Rendering every subcommand's help is what catches a subcommand flag
/// colliding with a global like `-q`, which otherwise only shows up at runtime.
#[test]
fn every_subcommand_help_renders() {
    let groups = [
        vec!["auth"],
        vec!["auth", "login"],
        vec!["auth", "status"],
        vec!["auth", "logout"],
        vec!["auth", "set-credential"],
        vec!["config"],
        vec!["accounts"],
        vec!["accounts", "list"],
        vec!["holdings"],
        vec!["holdings", "list"],
        vec!["positions"],
        vec!["positions", "list"],
        vec!["dividends"],
        vec!["dividends", "list"],
        vec!["activity"],
        vec!["activity", "list"],
        vec!["documents"],
        vec!["documents", "list"],
        vec!["documents", "download"],
        vec!["lots"],
        vec!["lots", "list"],
        vec!["transactions"],
        vec!["transactions", "list"],
        vec!["transfers"],
        vec!["transfers", "list"],
        vec!["net-worth"],
        vec!["ira"],
        vec!["summary"],
        vec!["status"],
        vec!["api"],
        vec!["api", "query"],
        vec!["mcp"],
        vec!["self-update"],
        vec!["completions"],
    ];
    for g in groups {
        let mut cmd = m1f();
        cmd.args(&g).arg("--help");
        cmd.assert()
            .success()
            .stdout(predicate::str::is_empty().not());
    }
}

#[test]
fn version_renders() {
    m1f().arg("--version").assert().success();
}

#[test]
fn usage_error_exits_2_with_json_error_dto() {
    m1f()
        .args(["--json", "not-a-command"])
        .assert()
        .code(2)
        .stderr(predicate::str::is_empty().not());
}

#[test]
fn info_emits_cli_info_v1() {
    let out = m1f().arg("info").output().expect("runs");
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("info emits JSON");
    assert_eq!(v["schema"], "cli-info/v1");
    assert_eq!(v["name"], "m1f");
    assert_eq!(v["spec"], "piekstra-cli/1");
    assert_eq!(v["auth"]["required"], true);
    // The password login is blocked at M1's edge (docs/api.md, Trap 7); the
    // browser session, captured through a sign-in window, is the login an
    // agent should point the owner at (cli-common DESIGN.md §2.2).
    assert_eq!(v["auth"]["method"], "browser-session");
    assert_eq!(v["auth"]["login_hint"], "m1f auth login --browser");
    let caps: Vec<&str> = v["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    for expected in [
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
        "mcp",
    ] {
        assert!(caps.contains(&expected), "missing capability {expected}");
    }
    // Declares the documents/v1 profile so a driver can consume it generically.
    let profiles: Vec<&str> = v["profiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap())
        .collect();
    assert!(profiles.contains(&"documents/v1"), "{profiles:?}");
}

#[test]
fn completions_render_for_zsh() {
    m1f()
        .args(["completions", "zsh"])
        .assert()
        .success()
        .stdout(predicate::str::contains("m1f"));
}

/// The read-only guard must fire before the keychain or network is touched —
/// which is exactly why this test can run offline at all.
#[test]
fn api_query_refuses_a_mutation_before_touching_credentials() {
    m1f()
        .args(["api", "query", "mutation Sell { sellAll { ok } }"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("read-only"));
}

#[test]
fn api_query_refuses_a_subscription() {
    m1f()
        .args(["api", "query", "subscription S { ticks { price } }"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("read-only"));
}

#[test]
fn api_query_rejects_bad_variables_before_the_network() {
    m1f()
        .args(["api", "query", "{ viewer { id } }", "--variables", "[1,2]"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("JSON object"));
}

#[test]
fn api_query_json_error_dto_is_a_single_document() {
    let out = m1f()
        .args(["--json", "api", "query", "mutation M { x }"])
        .output()
        .expect("runs");
    assert_eq!(out.status.code(), Some(2));
    // Exactly one JSON document on stdout, carrying the error contract.
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON doc");
    assert_eq!(v["error"]["code"], "usage");
    assert!(v["error"]["message"]
        .as_str()
        .unwrap()
        .contains("read-only"));
}

/// Date flags are validated before anything is spent, so a typo can't cost a
/// request or a credential prompt.
#[test]
fn bad_date_flags_fail_before_the_keychain() {
    for cmd in [
        ["activity", "list"],
        ["accounts", "list"],
        ["lots", "list"],
        ["dividends", "list"],
    ] {
        m1f()
            .args(cmd)
            .args(["--since", "not-a-date"])
            .assert()
            .code(2);
    }
}

/// A position has no date, so `positions list` takes no range flags: a
/// window it would silently ignore is refused at parse time instead.
#[test]
fn positions_list_refuses_a_date_window() {
    for flag in ["--since", "--until"] {
        m1f()
            .args(["positions", "list", flag, "2026-01-01"])
            .assert()
            .code(2);
    }
}

/// `lots list` rejects contradictory scope flags at parse time, before the
/// keychain or network.
#[test]
fn lots_open_and_closed_conflict() {
    m1f()
        .args(["lots", "list", "--open", "--closed"])
        .assert()
        .code(2);
}

/// `documents list --type` validates the enum spelling before any request.
#[test]
fn documents_list_rejects_an_unknown_type() {
    m1f()
        .args(["documents", "list", "--type", "nope"])
        .assert()
        .code(2);
}

#[test]
fn inverted_date_range_is_a_usage_error() {
    m1f()
        .args([
            "activity",
            "list",
            "--since",
            "2026-08-01",
            "--until",
            "2026-07-01",
        ])
        .assert()
        .code(2);
}

#[test]
fn documents_download_needs_an_id_or_all() {
    m1f()
        .args(["documents", "download"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--all"));
}

#[test]
fn documents_download_all_refuses_stdout() {
    m1f()
        .args(["documents", "download", "--all", "-o", "-"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("stdout"));
}

#[test]
fn unknown_config_key_is_a_usage_error() {
    m1f()
        .args(["config", "set", "nonsense", "value"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unknown config key"));
}

#[test]
fn config_path_needs_no_credentials() {
    m1f()
        .args(["config", "path"])
        .assert()
        .success()
        .stdout(predicate::str::contains("m1f"));
}

/// The browser session is several kilobytes — longer than a terminal line —
/// so without `--browser` it must come from a pipe or the environment; asking
/// for it with no source is a usage error naming both routes, before the
/// keychain or network.
#[test]
fn a_browser_session_login_needs_an_explicit_source() {
    m1f()
        .args(["auth", "login", "--browser-session"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("`m1f auth login --browser`"))
        .stderr(predicate::str::contains("pbpaste"));
}

/// `--browser` takes the session from the sign-in window, so a second source
/// or the password login's flags beside it are refused by the parser: exit 2
/// before the keychain is read, Chrome is launched or M1 is asked.
#[test]
fn a_browser_login_refuses_other_sources_and_the_password_flags() {
    for extra in [
        &["--stdin"][..],
        &["--from-env", "M1F_TEST_SESSION"],
        &["--username", "owner@example.invalid"],
        &["--code", "000000"],
    ] {
        for lead in [&["--browser"][..], &["--browser", "--browser-session"]] {
            m1f()
                .args(["auth", "login"])
                .args(lead)
                .args(extra)
                .env("M1F_TEST_SESSION", "{}")
                .write_stdin("{}")
                .assert()
                .code(2)
                .stderr(predicate::str::contains("cannot be used with"));
        }
    }
}

/// `--browser` is the primary route in the help an owner reads, with what it
/// does and the Chrome override; the DevTools route follows as the fallback.
#[test]
fn login_help_leads_with_the_browser_route() {
    let out = m1f()
        .args(["auth", "login", "--help"])
        .output()
        .expect("runs");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(
        help.lines().any(|l| l.trim() == "--browser"),
        "no --browser option in:\n{help}"
    );
    for needle in [
        "m1f auth login --browser\n",
        "https://dashboard.m1.com",
        "closes the tab",
        "M1F_CHROME",
        "--overwrite",
        "Without Chrome",
    ] {
        assert!(help.contains(needle), "missing {needle:?} in:\n{help}");
    }
    let browser = help.find("m1f auth login --browser\n").unwrap();
    let devtools = help.find("pbpaste").unwrap();
    assert!(browser < devtools, "--browser must come first:\n{help}");
    // The short help names the flag too.
    let out = m1f().args(["auth", "login", "-h"]).output().expect("runs");
    let short = String::from_utf8_lossy(&out.stdout);
    assert!(
        short
            .lines()
            .any(|l| l.trim_start().starts_with("--browser ")),
        "{short}"
    );
}

/// A mis-copied session is refused from its own bytes — before the keychain
/// is read or M1 is asked — with the fix named.
#[test]
fn a_mis_copied_browser_session_fails_before_the_keychain() {
    for junk in ["", "two words", "{not json", r#"{"theme":"dark"}"#] {
        m1f()
            .args(["auth", "login", "--browser-session", "--stdin"])
            .write_stdin(junk)
            .assert()
            .code(2);
    }
}

/// The browser session carries no username and no emailed code: those flags
/// belong to the password login and are refused beside it at parse time.
#[test]
fn a_browser_session_login_refuses_the_password_flags() {
    for extra in [["--code", "123456"], ["--username", "x@example.invalid"]] {
        m1f()
            .args(["auth", "login", "--browser-session", "--stdin"])
            .args(extra)
            .assert()
            .code(2);
    }
}

/// The capture steps live in the help an owner reads when the login fails.
#[test]
fn login_help_carries_the_devtools_capture_steps() {
    let out = m1f()
        .args(["auth", "login", "--help"])
        .output()
        .expect("runs");
    let help = String::from_utf8_lossy(&out.stdout);
    for needle in [
        "--browser-session",
        "@@auth0spajs@@::",
        "lens.m1finance.com",
        "pbpaste | m1f auth login --browser-session --stdin",
        "private",
    ] {
        assert!(help.contains(needle), "missing {needle:?} in:\n{help}");
    }
}

/// A password must never be accepted on argv — it would land in shell history
/// and in every process listing on the machine.
#[test]
fn login_offers_no_password_flag() {
    let out = m1f()
        .args(["auth", "login", "--help"])
        .output()
        .expect("runs");
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(!help.contains("--password"), "argv password flag present");
    // The sanctioned ingestion paths are present instead.
    assert!(help.contains("--stdin"), "{help}");
    assert!(help.contains("--from-env"), "{help}");
}
