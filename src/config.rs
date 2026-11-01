//! Non-secret settings for `m1f`, persisted to
//! `~/.config/m1f/config.json` via `pk_cli_config::ConfigStore`.
//!
//! Nothing here is a secret. Tokens and the pending-MFA session live only in
//! the OS keychain (`piekstra.m1f`); this file holds the account identity and
//! a couple of knobs.

use serde::{Deserialize, Serialize};

/// M1's web/mobile GraphQL backend. This is the endpoint the first-party web
/// app talks to; there is no official public API (see `docs/api.md`). It is a
/// non-secret default and may be overridden with `config set base_url <URL>`
/// or the `M1F_BASE_URL` env var for testing.
pub const DEFAULT_BASE_URL: &str = "https://lens.m1.com/graphql";

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Login identity (email). The keychain account key for the token bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Default account id for account-scoped reads, overridable per command
    /// with `--account`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Override the GraphQL endpoint. Omitted → `DEFAULT_BASE_URL`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    /// Re-authenticate automatically when a token has expired but a refresh
    /// token is still stored. On by default; turn off to force explicit
    /// `auth login`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_login: Option<bool>,
}

impl Config {
    /// The GraphQL endpoint: env override, then config, then the baked default.
    pub fn base_url(&self) -> String {
        std::env::var("M1F_BASE_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| self.base_url.clone())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
    }

    pub fn auto_login(&self) -> bool {
        self.auto_login.unwrap_or(true)
    }

    /// The known config keys, for `config set`/`unset` validation and error
    /// messages. Kept next to the fields so a new setting is a one-line change.
    pub const KEYS: &'static [&'static str] = &["username", "account", "base_url", "auto_login"];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_defaults_when_unset() {
        // Guard against a leaked env override from the surrounding shell.
        let cfg = Config::default();
        if std::env::var("M1F_BASE_URL").is_err() {
            assert_eq!(cfg.base_url(), DEFAULT_BASE_URL);
        }
    }

    #[test]
    fn config_base_url_is_used_when_no_env() {
        let cfg = Config {
            base_url: Some("https://example.test/graphql".into()),
            ..Config::default()
        };
        if std::env::var("M1F_BASE_URL").is_err() {
            assert_eq!(cfg.base_url(), "https://example.test/graphql");
        }
    }

    #[test]
    fn auto_login_defaults_on() {
        assert!(Config::default().auto_login());
        assert!(!Config {
            auto_login: Some(false),
            ..Config::default()
        }
        .auto_login());
    }
}
