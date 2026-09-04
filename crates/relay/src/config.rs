//! Relay configuration: one TOML file (`docs/stage0-mvp-plan.md` §6).
//!
//! Upstreams are a list with `kind = "owned" | "public"`, `transport =
//! "https" | "http" | "onion"` and per-node caps. Caps default to the
//! public-node rules (`.claude/rules/public-nodes.md` §3): a missing cap means
//! the default, never "unlimited". Opted-out hosts are refused at load time,
//! not merely deprioritised.

use std::collections::HashSet;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Identifying `User-Agent` sent on every upstream request (rule 4).
pub const DEFAULT_USER_AGENT: &str = concat!(
    "mnr-relay/",
    env!("CARGO_PKG_VERSION"),
    " (+https://mnr.network/upstreams)"
);
/// The disclosure link every User-Agent must carry, override included.
const UA_LINK: &str = "(+https://mnr.network/upstreams)";

#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Invalid(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "cannot read config: {e}"),
            Self::Parse(e) => write!(f, "cannot parse config: {e}"),
            Self::Invalid(why) => write!(f, "invalid config: {why}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the relay listens on. TLS is terminated in front of it.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Override the identifying User-Agent. Must still identify mnr.
    #[serde(default)]
    pub user_agent: Option<String>,
    /// Local Tor SOCKS5 endpoint, required if any upstream is `onion`.
    #[serde(default)]
    pub tor_socks: Option<SocketAddr>,
    #[serde(default)]
    pub probe: ProbeConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub chain: ChainConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub billing: BillingConfig,
    /// Hosts that asked to be removed (rule 5). Any upstream whose host is
    /// listed here is refused at load.
    #[serde(default)]
    pub opt_out: Vec<String>,
    pub upstreams: Vec<UpstreamConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// Path to the SQLite token/usage database. When set, tokens are managed
    /// with `mnr-relay token ...` and `--dev-token` is refused.
    pub database: Option<PathBuf>,
}

/// The relay's own header chain (`docs/stage0-mvp-plan.md` §4): built once
/// by majority from the upstreams, extended at the tip every probe round.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// Where the chain is persisted (`mnr-core` byte format, ~280 MB on
    /// mainnet). Unset keeps it in memory only: every restart rebuilds.
    pub path: Option<PathBuf>,
    /// Headers fetched per `get_block_headers_range` call while building.
    /// monerod refuses more than 1000 on a restricted node.
    #[serde(default = "default_chain_batch")]
    pub batch: u64,
}

/// The storefront (`docs/stage0-mvp-plan.md` §5 payments). Free tokens
/// need only `[auth] database`; Pro invoices also need `wallet_rpc`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BillingConfig {
    /// View-only `monero-wallet-rpc` JSON-RPC URL on loopback
    /// (`--disable-rpc-login`). Unset disables Pro invoices.
    pub wallet_rpc: Option<String>,
    /// Price of one Pro month in atomic units. $9 is the promise; this
    /// figure is set by hand (no exchange-rate lookups).
    #[serde(default = "default_pro_price")]
    pub pro_price_atomic: u64,
    /// Confirmations before a payment counts (plan §5: 10).
    #[serde(default = "default_confirmations")]
    pub confirmations: u32,
    /// Ceiling on Free tokens issued per day, all clients together.
    #[serde(default = "default_free_per_day")]
    pub free_per_day: u64,
    /// Issuances (free tokens and invoices) per client key per hour.
    #[serde(default = "default_per_client")]
    pub per_client_per_hour: u32,
    /// Longest Pro purchase, in months.
    #[serde(default = "default_months_max")]
    pub months_max: u32,
    /// Header a trusted proxy sets with the client address (Cloudflare's
    /// `CF-Connecting-IP`, forwarded by Caddy). Unset: the socket peer.
    /// Only meaningful when the relay listens on loopback behind that proxy.
    pub client_ip_header: Option<String>,
    /// 32 random bytes the Pro tokens are derived from; created on first
    /// start. Without it derived tokens change on every restart.
    pub secret_file: Option<PathBuf>,
    /// Origin allowed to call the storefront from a browser.
    #[serde(default = "default_cors_origin")]
    pub cors_origin: Option<String>,
}

fn default_pro_price() -> u64 {
    60_000_000_000
}
fn default_confirmations() -> u32 {
    10
}
fn default_free_per_day() -> u64 {
    2000
}
fn default_per_client() -> u32 {
    3
}
fn default_months_max() -> u32 {
    12
}
fn default_cors_origin() -> Option<String> {
    Some("https://mnr.network".to_owned())
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            wallet_rpc: None,
            pro_price_atomic: default_pro_price(),
            confirmations: default_confirmations(),
            free_per_day: default_free_per_day(),
            per_client_per_hour: default_per_client(),
            months_max: default_months_max(),
            client_ip_header: None,
            secret_file: None,
            cors_origin: default_cors_origin(),
        }
    }
}

/// Prometheus exposition (`docs/stage0-mvp-plan.md` §6). Aggregate series
/// only; served on its own listener so it is never reachable through the
/// public address.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address for `/metrics`. Unset disables the exporter.
    pub listen: Option<SocketAddr>,
}

/// In-memory response cache (`docs/stage0-mvp-plan.md` §5).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Ceiling for the immutable tier (blocks, headers, txs) in bytes.
    #[serde(default = "default_cache_bytes")]
    pub max_bytes: u64,
}

fn default_cache_bytes() -> u64 {
    1 << 30
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_cache_bytes(),
        }
    }
}

fn default_chain_batch() -> u64 {
    1000
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self {
            path: None,
            batch: default_chain_batch(),
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:18089".parse().expect("valid literal")
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfig {
    /// Seconds between probe rounds (plan §3: 15).
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Per-probe timeout for clearnet upstreams (plan §3: 2 s).
    #[serde(default = "default_clearnet_timeout")]
    pub clearnet_timeout_ms: u64,
    /// Per-probe timeout for onion upstreams (plan §3: 8 s).
    #[serde(default = "default_onion_timeout")]
    pub onion_timeout_ms: u64,
    /// Upstreams that must agree on a tip hash for it to be the quorum tip
    /// (plan §3: 3). Below this the relay is in degraded mode.
    #[serde(default = "default_min_agree")]
    pub min_agree: usize,
}

fn default_interval() -> u64 {
    15
}
fn default_clearnet_timeout() -> u64 {
    2000
}
fn default_onion_timeout() -> u64 {
    8000
}
fn default_min_agree() -> usize {
    3
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval_secs: default_interval(),
            clearnet_timeout_ms: default_clearnet_timeout(),
            onion_timeout_ms: default_onion_timeout(),
            min_agree: default_min_agree(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A node we run. Preferred for streams and tie-breaks.
    Owned,
    /// A community node. Capped, identified to, opt-out honoured.
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Https,
    Http,
    /// Reached through the local Tor SOCKS proxy; light calls only.
    Onion,
}

/// Per-upstream ceilings (rule 3). Defaults are the public-node caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Caps {
    /// Light (non-stream) requests per second.
    #[serde(default = "default_rps_light")]
    pub rps_light: u32,
    /// Concurrent `get_blocks.bin` streams.
    #[serde(default = "default_max_streams")]
    pub max_streams: u32,
    /// Stream bandwidth, MB/s. Published in the status feed; enforcement
    /// lands with the streaming rewrite (plan §7 week 4), see `upstream`.
    #[serde(default = "default_mbps")]
    pub mbps: u32,
}

fn default_rps_light() -> u32 {
    5
}
fn default_max_streams() -> u32 {
    2
}
fn default_mbps() -> u32 {
    10
}

impl Default for Caps {
    fn default() -> Self {
        Self {
            rps_light: default_rps_light(),
            max_streams: default_max_streams(),
            mbps: default_mbps(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Short unique name, used in logs and the public upstreams page.
    pub name: String,
    /// Base URL, e.g. `https://node.example:18081` or `http://<x>.onion:18081`.
    pub url: String,
    pub kind: Kind,
    pub transport: Transport,
    #[serde(default)]
    pub caps: Caps,
}

impl UpstreamConfig {
    /// Where rule 5's opt-out signal lives: `/.well-known/mnr-optout` on the
    /// upstream's host (its web port, not the RPC port), over the scheme
    /// the transport implies.
    pub fn opt_out_url(&self) -> Option<String> {
        let scheme = match self.transport {
            Transport::Https => "https",
            Transport::Http | Transport::Onion => "http",
        };
        Some(format!(
            "{scheme}://{}/.well-known/mnr-optout",
            self.host()?
        ))
    }

    /// Host part of the URL, for opt-out matching.
    pub fn host(&self) -> Option<&str> {
        let rest = self.url.split_once("://")?.1;
        let host_port = rest.split('/').next()?;
        Some(host_port.rsplit_once(':').map_or(host_port, |(h, p)| {
            if p.chars().all(|c| c.is_ascii_digit()) {
                h
            } else {
                host_port
            }
        }))
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let cfg: Config = toml::from_str(text).map_err(ConfigError::Parse)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn user_agent(&self) -> &str {
        self.user_agent.as_deref().unwrap_or(DEFAULT_USER_AGENT)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let invalid = |why: String| Err(ConfigError::Invalid(why));
        if self.upstreams.is_empty() {
            return invalid("at least one upstream is required".into());
        }
        if self.probe.min_agree == 0 {
            return invalid("probe.min_agree must be at least 1".into());
        }
        if self.chain.batch == 0 || self.chain.batch > 1000 {
            return invalid("chain.batch must be between 1 and 1000".into());
        }
        if self.metrics.listen == Some(self.listen) {
            return invalid("metrics.listen must differ from the public listen address".into());
        }
        if self.billing.client_ip_header.is_some() && !self.listen.ip().is_loopback() {
            return invalid(
                "billing.client_ip_header is only safe when listen is a loopback address behind the proxy that sets it".into(),
            );
        }
        if self.billing.per_client_per_hour == 0 || self.billing.months_max == 0 {
            return invalid("billing.per_client_per_hour and months_max must be non-zero".into());
        }
        if self.upstreams.len() < self.probe.min_agree {
            return invalid(format!(
                "{} upstreams cannot reach probe.min_agree = {}; the relay would be degraded forever",
                self.upstreams.len(),
                self.probe.min_agree
            ));
        }
        if let Some(ua) = &self.user_agent {
            if !ua.starts_with("mnr-relay/") || !ua.contains(UA_LINK) {
                return invalid(format!(
                    "user_agent must start with `mnr-relay/` and contain `{UA_LINK}` (rule 4)"
                ));
            }
        }
        let opt_out: HashSet<&str> = self.opt_out.iter().map(String::as_str).collect();
        let mut names = HashSet::new();
        for u in &self.upstreams {
            if !names.insert(u.name.as_str()) {
                return invalid(format!("duplicate upstream name `{}`", u.name));
            }
            let Some(host) = u.host() else {
                return invalid(format!("upstream `{}`: url has no host", u.name));
            };
            if opt_out.contains(host) {
                return invalid(format!(
                    "upstream `{}`: host {host} is on the opt-out list (rule 5)",
                    u.name
                ));
            }
            let scheme_ok = match u.transport {
                Transport::Https => u.url.starts_with("https://"),
                Transport::Http => u.url.starts_with("http://"),
                Transport::Onion => u.url.starts_with("http://") && host.ends_with(".onion"),
            };
            if !scheme_ok {
                return invalid(format!(
                    "upstream `{}`: url `{}` does not match transport {:?}",
                    u.name, u.url, u.transport
                ));
            }
            if u.transport == Transport::Onion && self.tor_socks.is_none() {
                return invalid(format!(
                    "upstream `{}` is onion but tor_socks is not set",
                    u.name
                ));
            }
            if u.transport != Transport::Onion && host.ends_with(".onion") {
                return invalid(format!(
                    "upstream `{}`: .onion host must use transport = \"onion\"",
                    u.name
                ));
            }
            if u.caps.rps_light == 0 || u.caps.max_streams == 0 || u.caps.mbps == 0 {
                return invalid(format!("upstream `{}`: caps must be non-zero", u.name));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One upstream needs min_agree = 1 to be a valid config.
    const PROBE1: &str = "[probe]\nmin_agree = 1\n";

    const MINIMAL: &str = r#"
[[upstreams]]
name = "cake"
url = "https://xmr-node.cakewallet.com:18081"
kind = "public"
transport = "https"
"#;

    #[test]
    fn minimal_config_gets_public_node_defaults() {
        let c = Config::parse(&format!("{PROBE1}{MINIMAL}")).unwrap();
        assert_eq!(c.listen.port(), 18089);
        assert_eq!(c.probe.interval_secs, 15);
        assert_eq!(c.probe.min_agree, 1);
        let u = &c.upstreams[0];
        assert_eq!(u.caps, Caps::default());
        assert_eq!(u.caps.rps_light, 5);
        assert_eq!(u.host(), Some("xmr-node.cakewallet.com"));
        assert!(c.user_agent().starts_with("mnr-relay/"));
        assert!(c.user_agent().contains(UA_LINK));
    }

    /// The shipped example must always parse: a section added above a
    /// top-level key once swallowed `opt_out` into `[metrics]`.
    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../relay.example.toml");
        let c = Config::parse(text).unwrap();
        assert_eq!(c.upstreams.len(), 5);
        assert!(c.opt_out.is_empty());
        assert_eq!(c.metrics.listen.map(|a| a.port()), Some(9187));
        assert_eq!(c.chain.path.as_deref(), Some(Path::new("headers.mnrh")));
        assert_eq!(c.cache.max_bytes, 1 << 30);
    }

    #[test]
    fn opt_out_url_is_the_host_web_root() {
        let c = Config::parse(&format!("{PROBE1}{MINIMAL}")).unwrap();
        assert_eq!(
            c.upstreams[0].opt_out_url().as_deref(),
            Some("https://xmr-node.cakewallet.com/.well-known/mnr-optout")
        );
        let http = MINIMAL
            .replace(
                "https://xmr-node.cakewallet.com:18081",
                "http://node.example:18089",
            )
            .replace("transport = \"https\"", "transport = \"http\"");
        let c = Config::parse(&format!("{PROBE1}{http}")).unwrap();
        assert_eq!(
            c.upstreams[0].opt_out_url().as_deref(),
            Some("http://node.example/.well-known/mnr-optout")
        );
    }

    #[test]
    fn opted_out_host_is_refused_at_load() {
        let text = format!("opt_out = [\"xmr-node.cakewallet.com\"]\n{PROBE1}{MINIMAL}");
        let err = Config::parse(&text).unwrap_err().to_string();
        assert!(err.contains("opt-out"), "{err}");
    }

    #[test]
    fn onion_requires_tor_socks_and_matching_scheme() {
        let onion = r#"
[probe]
min_agree = 1
[[upstreams]]
name = "o"
url = "http://abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz234567.onion:18081"
kind = "public"
transport = "onion"
"#;
        assert!(Config::parse(onion)
            .unwrap_err()
            .to_string()
            .contains("tor_socks"));
        let ok = format!("tor_socks = \"127.0.0.1:9050\"\n{onion}");
        assert!(Config::parse(&ok).is_ok());
        let wrong = onion.replace("transport = \"onion\"", "transport = \"http\"");
        assert!(
            Config::parse(&format!("tor_socks = \"127.0.0.1:9050\"\n{wrong}"))
                .unwrap_err()
                .to_string()
                .contains("transport = \"onion\"")
        );
    }

    #[test]
    fn scheme_must_match_transport_and_names_unique() {
        let bad = MINIMAL.replace("transport = \"https\"", "transport = \"http\"");
        assert!(Config::parse(&format!("{PROBE1}{bad}")).is_err());
        let dup = format!("{PROBE1}{MINIMAL}{MINIMAL}");
        assert!(Config::parse(&dup)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
    }

    #[test]
    fn user_agent_override_must_still_identify_us() {
        let text = format!("user_agent = \"Mozilla/5.0\"\n{PROBE1}{MINIMAL}");
        assert!(Config::parse(&text).is_err());
        let text = format!("user_agent = \"mnr-relay/0.1 (mnr.network)\"\n{PROBE1}{MINIMAL}");
        assert!(
            Config::parse(&text).is_err(),
            "link must be the upstreams page"
        );
        let text = format!(
            "user_agent = \"mnr-relay/0.1 (+https://mnr.network/upstreams)\"\n{PROBE1}{MINIMAL}"
        );
        assert!(Config::parse(&text).is_ok());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = format!("logging = true\n{PROBE1}{MINIMAL}");
        assert!(Config::parse(&text).is_err());
    }

    #[test]
    fn too_few_upstreams_for_min_agree_is_refused() {
        let err = Config::parse(MINIMAL).unwrap_err().to_string();
        assert!(err.contains("min_agree"), "{err}");
    }

    #[test]
    fn auth_database_is_optional_and_strict() {
        let c = Config::parse(&format!(
            "[auth]\ndatabase = \"relay.db\"\n{PROBE1}{MINIMAL}"
        ))
        .unwrap();
        assert_eq!(c.auth.database.as_deref(), Some(Path::new("relay.db")));
        let c = Config::parse(&format!("{PROBE1}{MINIMAL}")).unwrap();
        assert_eq!(c.auth.database, None);
        let err = Config::parse(&format!("[auth]\npath = \"x.db\"\n{PROBE1}{MINIMAL}"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown field"), "{err}");
    }
}
