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
use std::path::Path;

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
    /// Hosts that asked to be removed (rule 5). Any upstream whose host is
    /// listed here is refused at load.
    #[serde(default)]
    pub opt_out: Vec<String>,
    pub upstreams: Vec<UpstreamConfig>,
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
    /// Stream bandwidth, MB/s.
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
}
