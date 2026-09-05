//! Credentials and principals (`docs/stage0-mvp-plan.md` §5; gateway plan §3.1).
//!
//! A client presents a token either in the path (`/v1/<token>/json_rpc`) or as
//! the password of HTTP Basic auth on the bare path (`--daemon-login`). Both
//! carry the same 256-bit token. The relay never holds raw tokens at rest:
//! [`token_hash`] is the SHA-256 that stores, quota rows and error samples
//! use, and only an 8-character prefix of it ever appears in a log line.
//!
//! [`TokenStore`] is the seam between this module and persistence; the
//! SQLite-backed store implements it, and [`MemoryTokenStore`] serves tests
//! and local runs.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Subscription tier (plan §5 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Free,
    Pro,
}

impl Tier {
    /// Nominal burst, requests per second.
    pub const fn burst_rps(self) -> u32 {
        match self {
            Self::Free => 5,
            Self::Pro => 25,
        }
    }

    /// Monthly allowance in work units.
    pub const fn monthly_wu(self) -> u64 {
        match self {
            Self::Free => 500_000,
            Self::Pro => 10_000_000,
        }
    }

    /// Concurrent `get_blocks.bin` streams (enforced by the limiter).
    pub const fn max_streams(self) -> u32 {
        match self {
            Self::Free => 1,
            Self::Pro => 3,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
        }
    }
}

/// An authenticated client, as far as the request path needs to know.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Store-assigned id; used for quota and burst bookkeeping.
    pub id: i64,
    pub tier: Tier,
    /// First 8 hex characters of [`token_hash`]: the only handle that may
    /// appear in an error sample.
    pub handle: String,
}

/// Why a token was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Token-shaped but unknown: HTTP 401.
    Unknown,
    /// Known but expired or suspended: HTTP 403, JSON-RPC `-32001`.
    Expired,
}

/// Persistence seam for tokens. Implementations compare hashes, never raw
/// tokens, and must be cheap: this is called on every request.
pub trait TokenStore: Send + Sync {
    /// Resolve a token hash to a principal.
    fn authenticate(&self, hash: &[u8; 32]) -> Result<Principal, AuthError>;
}

/// SHA-256 of the raw token string. Stores and quotas key on this.
pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// The 8-character log handle for a token hash.
pub fn handle(hash: &[u8; 32]) -> String {
    hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Shape check before any lookup: `sub_` + base58 of 32 bytes (43–44 chars).
/// Anything else is refused before the store is consulted.
pub fn looks_like_token(s: &str) -> bool {
    const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let Some(body) = s.strip_prefix("sub_") else {
        return false;
    };
    (40..=48).contains(&body.len()) && body.bytes().all(|b| B58.contains(&b))
}

/// Pull a token out of a request: the path segment if present, else the
/// `Authorization` header.
///
/// - **Basic**: the token may be the password or the username.
/// - **Digest**: the token must be the **username** (`--daemon-login
///   <token>:x`). Stock Monero wallets speak only Digest, and Digest cannot
///   be verified against a stored hash without the server holding a
///   password-equivalent, which invariant 6 forbids. With the token as the
///   username it travels in clear over TLS exactly as Basic would, the relay
///   hashes and looks it up, and the digest `response` (over an arbitrary
///   password) is not what authenticates. The nonce in the challenge is
///   random so clients that insist on freshness are satisfied.
pub fn extract_token(path_token: Option<&str>, authorization: Option<&str>) -> Option<String> {
    if let Some(t) = path_token {
        return looks_like_token(t).then(|| t.to_owned());
    }
    let authz = authorization?.trim();
    if let Some(creds) = authz.strip_prefix("Basic ") {
        let decoded = base64_decode(creds.trim())?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded.split_once(':').unwrap_or((&decoded, ""));
        return if looks_like_token(pass) {
            Some(pass.to_owned())
        } else if looks_like_token(user) {
            Some(user.to_owned())
        } else {
            None
        };
    }
    if let Some(params) = authz.strip_prefix("Digest ") {
        let user = digest_param(params, "username")?;
        return looks_like_token(&user).then_some(user);
    }
    None
}

/// The value of `name` in a Digest parameter list (`k="v", k=v, …`).
fn digest_param(params: &str, name: &str) -> Option<String> {
    let mut rest = params;
    while !rest.is_empty() {
        let rest_trim = rest.trim_start_matches([' ', ',']);
        let eq = rest_trim.find('=')?;
        let key = rest_trim[..eq].trim();
        let after = &rest_trim[eq + 1..];
        let (value, remaining) = if let Some(q) = after.strip_prefix('"') {
            let end = q.find('"')?;
            (&q[..end], &q[end + 1..])
        } else {
            let end = after.find(',').unwrap_or(after.len());
            (after[..end].trim(), &after[end..])
        };
        if key.eq_ignore_ascii_case(name) {
            return Some(value.to_owned());
        }
        rest = remaining;
    }
    None
}

/// In-memory store for tests and local runs (`--dev-token` in `main`).
#[derive(Default)]
pub struct MemoryTokenStore {
    by_hash: HashMap<[u8; 32], Principal>,
    expired: HashMap<[u8; 32], ()>,
}

impl MemoryTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a raw token; returns the principal it maps to.
    pub fn insert(&mut self, token: &str, tier: Tier) -> Principal {
        let hash = token_hash(token);
        let p = Principal {
            id: self.by_hash.len() as i64 + 1,
            tier,
            handle: handle(&hash),
        };
        self.by_hash.insert(hash, p.clone());
        p
    }

    #[cfg(test)]
    pub fn expire(&mut self, token: &str) {
        let hash = token_hash(token);
        self.by_hash.remove(&hash);
        self.expired.insert(hash, ());
    }
}

impl TokenStore for MemoryTokenStore {
    fn authenticate(&self, hash: &[u8; 32]) -> Result<Principal, AuthError> {
        if let Some(p) = self.by_hash.get(hash) {
            return Ok(p.clone());
        }
        if self.expired.contains_key(hash) {
            return Err(AuthError::Expired);
        }
        Err(AuthError::Unknown)
    }
}

/// Standard base64 (with or without padding); enough for a Basic header.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in s.bytes() {
        if b == b'=' {
            break;
        }
        let v = T.iter().position(|&t| t == b)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "sub_4k9ZQ2pQ7wq1sDhBfT8zPxT5Y3v7g9jN2mR6cLbVwXyU"; // 44 chars body

    #[test]
    fn token_shape_is_checked_before_lookup() {
        assert!(looks_like_token(TOKEN));
        assert!(!looks_like_token("sub_"));
        assert!(!looks_like_token("json_rpc"));
        assert!(!looks_like_token(
            "sub_0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl"
        )); // 0, O, I, l
        assert!(!looks_like_token(&format!("{TOKEN}/json_rpc")));
    }

    #[test]
    fn path_token_wins_and_basic_auth_password_is_the_fallback() {
        assert_eq!(extract_token(Some(TOKEN), None).as_deref(), Some(TOKEN));
        assert_eq!(extract_token(Some("nope"), None), None);
        let basic = format!("Basic {}", b64(&format!("mnr:{TOKEN}")));
        assert_eq!(extract_token(None, Some(&basic)).as_deref(), Some(TOKEN));
        let as_user = format!("Basic {}", b64(&format!("{TOKEN}:")));
        assert_eq!(extract_token(None, Some(&as_user)).as_deref(), Some(TOKEN));
        let junk = format!("Basic {}", b64("user:password"));
        assert_eq!(extract_token(None, Some(&junk)), None);
        assert_eq!(extract_token(None, Some("Bearer x")), None);
    }

    #[test]
    fn memory_store_distinguishes_unknown_from_expired() {
        let mut s = MemoryTokenStore::new();
        let p = s.insert(TOKEN, Tier::Pro);
        assert_eq!(p.handle.len(), 8);
        assert_eq!(s.authenticate(&token_hash(TOKEN)), Ok(p));
        assert_eq!(
            s.authenticate(&token_hash("sub_other")),
            Err(AuthError::Unknown)
        );
        s.expire(TOKEN);
        assert_eq!(s.authenticate(&token_hash(TOKEN)), Err(AuthError::Expired));
    }

    #[test]
    fn handle_is_eight_hex_chars_of_the_hash() {
        let h = token_hash("x");
        let hd = handle(&h);
        assert_eq!(hd.len(), 8);
        assert!(hd.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    fn b64(s: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let mut n = 0u32;
            for (i, b) in chunk.iter().enumerate() {
                n |= (*b as u32) << (16 - 8 * i);
            }
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }
}
