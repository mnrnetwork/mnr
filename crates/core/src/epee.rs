//! `epee` — a read-only parser for monerod's epee *portable storage* binary
//! format, the encoding of every `.bin` daemon endpoint (`/get_outs.bin`,
//! `/get_o_indexes.bin`, `/get_blocks.bin`, …).
//!
//! The relay never re-encodes a `.bin` body; it is passed through verbatim.
//! Parsing exists for one reason: comparing two upstreams' answers to the same
//! request (`docs/stage0-mvp-plan.md` §4, `get_outs` agreement for Pro
//! tokens). Byte equality is not a safe comparator across monerod versions
//! (a new field appended by one node is not a lie), so answers are parsed into
//! a [`Value`] tree, volatile top-level keys are dropped with [`canonical`],
//! and the trees are compared.
//!
//! Format, as monerod writes it (`contrib/epee/include/storages/portable_storage_from_bin.h`):
//!
//! ```text
//! u32le 0x01011101 · u32le 0x01020101 · u8 version=1 · section
//! section  = varint count · count × (u8 name_len · name · entry)
//! entry    = u8 type · value              (type & 0x80 → array of `type & 0x7f`)
//! array    = varint count · count × value (elements carry no type byte)
//! varint   = low 2 bits of the first byte give the width: 1, 2, 4 or 8 bytes
//!            little-endian; the value is the whole word shifted right by 2
//! ```
//!
//! Every count is checked against the bytes that remain, nesting is bounded
//! by [`MAX_DEPTH`], and an unknown type byte is an error, never a panic: an
//! answer this parser cannot read is compared by nobody and annotated
//! `Mnr-Verify: none` by the relay.

use std::collections::BTreeMap;
use std::fmt;

/// First signature word.
pub const SIGNATURE_A: u32 = 0x0101_1101;
/// Second signature word.
pub const SIGNATURE_B: u32 = 0x0102_0101;
/// The only format version monerod has ever written.
pub const FORMAT_VERSION: u8 = 1;
/// Deepest nesting of sections/arrays accepted. monerod's own limit is 100;
/// no daemon response nests beyond a handful.
pub const MAX_DEPTH: usize = 32;

/// Top-level keys that differ between honest upstreams answering the same
/// request: RPC-payment credits, the node's current top hash, its
/// restricted-mode flag and the status string. Dropped by [`canonical`].
pub const VOLATILE_KEYS: &[&str] = &["credits", "top_hash", "untrusted", "status"];

const FLAG_ARRAY: u8 = 0x80;
const TYPE_I64: u8 = 1;
const TYPE_I32: u8 = 2;
const TYPE_I16: u8 = 3;
const TYPE_I8: u8 = 4;
const TYPE_U64: u8 = 5;
const TYPE_U32: u8 = 6;
const TYPE_U16: u8 = 7;
const TYPE_U8: u8 = 8;
const TYPE_F64: u8 = 9;
const TYPE_STRING: u8 = 10;
const TYPE_BOOL: u8 = 11;
const TYPE_OBJECT: u8 = 12;
const TYPE_ARRAY: u8 = 13;

/// A section: named entries, ordered by name so two trees compare
/// structurally regardless of the order a node wrote them in.
pub type Section = BTreeMap<String, Value>;

/// One decoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    I64(i64),
    I32(i32),
    I16(i16),
    I8(i8),
    U64(u64),
    U32(u32),
    U16(u16),
    U8(u8),
    /// IEEE-754 bits, so the tree stays `Eq`; see [`Value::as_f64`].
    F64(u64),
    Bool(bool),
    /// epee "string": arbitrary bytes (hashes and blobs travel this way).
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Section(Section),
}

impl Value {
    /// The float behind [`Value::F64`].
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::F64(bits) => Some(f64::from_bits(*bits)),
            _ => None,
        }
    }

    /// Any integer variant widened to `u64` (negative values are `None`).
    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Self::U64(v) => Some(v),
            Self::U32(v) => Some(u64::from(v)),
            Self::U16(v) => Some(u64::from(v)),
            Self::U8(v) => Some(u64::from(v)),
            Self::I64(v) => u64::try_from(v).ok(),
            Self::I32(v) => u64::try_from(v).ok(),
            Self::I16(v) => u64::try_from(v).ok(),
            Self::I8(v) => u64::try_from(v).ok(),
            _ => None,
        }
    }
}

/// Why a body could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The signature words are not epee's.
    Signature,
    /// A format version other than 1.
    Version(u8),
    /// The body ended inside a value, or a count exceeds the bytes left.
    Truncated,
    /// A type byte this parser does not know.
    UnknownType(u8),
    /// An entry name is not UTF-8.
    BadName,
    /// The inner type of an array-of-arrays does not carry the array flag.
    BadArray,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
    /// Bytes remain after the root section.
    Trailing,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature => f.write_str("not an epee portable-storage body"),
            Self::Version(v) => write!(f, "unsupported epee format version {v}"),
            Self::Truncated => f.write_str("truncated epee body"),
            Self::UnknownType(t) => write!(f, "unknown epee type {t:#04x}"),
            Self::BadName => f.write_str("epee entry name is not UTF-8"),
            Self::BadArray => f.write_str("epee nested array without array flag"),
            Self::TooDeep => f.write_str("epee nesting too deep"),
            Self::Trailing => f.write_str("bytes after the epee root section"),
        }
    }
}

impl std::error::Error for Error {}

/// Parse a complete portable-storage body into its root section.
pub fn parse(bytes: &[u8]) -> Result<Section, Error> {
    let mut cur = Cursor { bytes, pos: 0 };
    if cur.u32()? != SIGNATURE_A || cur.u32()? != SIGNATURE_B {
        return Err(Error::Signature);
    }
    let version = cur.u8()?;
    if version != FORMAT_VERSION {
        return Err(Error::Version(version));
    }
    let root = cur.section(0)?;
    if cur.pos != bytes.len() {
        return Err(Error::Trailing);
    }
    Ok(root)
}

/// The section without the given top-level keys. Pass [`VOLATILE_KEYS`] to
/// make two upstreams' answers to the same request comparable.
pub fn canonical(section: &Section, drop: &[&str]) -> Section {
    section
        .iter()
        .filter(|(k, _)| !drop.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&[u8], Error> {
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    /// epee varint: the low two bits of the first byte select the width.
    fn varint(&mut self) -> Result<u64, Error> {
        let first = self.bytes.get(self.pos).copied().ok_or(Error::Truncated)?;
        Ok(match first & 0b11 {
            0 => u64::from(self.u8()? >> 2),
            1 => u64::from(u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")) >> 2),
            2 => u64::from(self.u32()? >> 2),
            _ => self.u64()? >> 2,
        })
    }

    /// A count that must be satisfiable by the bytes left, each element
    /// costing at least `min_bytes`. Rejects absurd counts before allocating.
    fn count(&mut self, min_bytes: usize) -> Result<usize, Error> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| Error::Truncated)?;
        if n.checked_mul(min_bytes)
            .is_none_or(|need| need > self.remaining())
        {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    fn section(&mut self, depth: usize) -> Result<Section, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        // name_len + type byte is the smallest possible entry.
        let n = self.count(2)?;
        let mut out = Section::new();
        for _ in 0..n {
            let len = usize::from(self.u8()?);
            let name = std::str::from_utf8(self.take(len)?)
                .map_err(|_| Error::BadName)?
                .to_owned();
            let value = self.entry(depth)?;
            out.insert(name, value);
        }
        Ok(out)
    }

    /// A typed entry: type byte, then the value (or the array of values).
    fn entry(&mut self, depth: usize) -> Result<Value, Error> {
        let t = self.u8()?;
        if t & FLAG_ARRAY != 0 {
            self.array(t & !FLAG_ARRAY, depth)
        } else {
            self.value(t, depth)
        }
    }

    fn array(&mut self, elem: u8, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let n = self.count(min_size(elem)?)?;
        let mut out = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            out.push(self.value(elem, depth + 1)?);
        }
        Ok(Value::Array(out))
    }

    fn value(&mut self, t: u8, depth: usize) -> Result<Value, Error> {
        Ok(match t {
            TYPE_I64 => Value::I64(self.u64()? as i64),
            TYPE_I32 => Value::I32(self.u32()? as i32),
            TYPE_I16 => Value::I16(u16::from_le_bytes(self.take(2)?.try_into().expect("2")) as i16),
            TYPE_I8 => Value::I8(self.u8()? as i8),
            TYPE_U64 => Value::U64(self.u64()?),
            TYPE_U32 => Value::U32(self.u32()?),
            TYPE_U16 => Value::U16(u16::from_le_bytes(self.take(2)?.try_into().expect("2"))),
            TYPE_U8 => Value::U8(self.u8()?),
            TYPE_F64 => Value::F64(self.u64()?),
            TYPE_STRING => {
                let len = self.count(1)?;
                Value::Bytes(self.take(len)?.to_vec())
            }
            TYPE_BOOL => Value::Bool(self.u8()? != 0),
            TYPE_OBJECT => Value::Section(self.section(depth + 1)?),
            TYPE_ARRAY => {
                // Array of arrays: the inner type byte must itself be flagged.
                let inner = self.u8()?;
                if inner & FLAG_ARRAY == 0 {
                    return Err(Error::BadArray);
                }
                self.array(inner & !FLAG_ARRAY, depth + 1)?
            }
            other => return Err(Error::UnknownType(other)),
        })
    }
}

/// Smallest encoding of one value of type `t`, for count sanity checks.
fn min_size(t: u8) -> Result<usize, Error> {
    Ok(match t {
        TYPE_I64 | TYPE_U64 | TYPE_F64 => 8,
        TYPE_I32 | TYPE_U32 => 4,
        TYPE_I16 | TYPE_U16 => 2,
        TYPE_I8 | TYPE_U8 | TYPE_BOOL | TYPE_STRING | TYPE_OBJECT => 1,
        TYPE_ARRAY => 2,
        other => return Err(Error::UnknownType(other)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 9-byte header every body starts with.
    const HEADER: [u8; 9] = [0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01];

    /// A test-only writer, so round-trips exercise every type. The relay
    /// never encodes; this stays under `#[cfg(test)]`.
    fn varint(n: u64, out: &mut Vec<u8>) {
        if n < 1 << 6 {
            out.push((n as u8) << 2);
        } else if n < 1 << 14 {
            out.extend_from_slice(&(((n as u16) << 2) | 1).to_le_bytes());
        } else if n < 1 << 30 {
            out.extend_from_slice(&(((n as u32) << 2) | 2).to_le_bytes());
        } else {
            out.extend_from_slice(&((n << 2) | 3).to_le_bytes());
        }
    }

    fn type_of(v: &Value) -> u8 {
        match v {
            Value::I64(_) => TYPE_I64,
            Value::I32(_) => TYPE_I32,
            Value::I16(_) => TYPE_I16,
            Value::I8(_) => TYPE_I8,
            Value::U64(_) => TYPE_U64,
            Value::U32(_) => TYPE_U32,
            Value::U16(_) => TYPE_U16,
            Value::U8(_) => TYPE_U8,
            Value::F64(_) => TYPE_F64,
            Value::Bool(_) => TYPE_BOOL,
            Value::Bytes(_) => TYPE_STRING,
            Value::Section(_) => TYPE_OBJECT,
            Value::Array(_) => TYPE_ARRAY,
        }
    }

    fn write_value(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::I64(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::I32(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::I16(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::I8(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::U64(x) | Value::F64(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::U32(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::U16(x) => out.extend_from_slice(&x.to_le_bytes()),
            Value::U8(x) => out.push(*x),
            Value::Bool(b) => out.push(u8::from(*b)),
            Value::Bytes(b) => {
                varint(b.len() as u64, out);
                out.extend_from_slice(b);
            }
            Value::Section(s) => write_section(s, out),
            Value::Array(items) => {
                // Only reached for arrays nested inside arrays: they carry
                // their own flagged type byte.
                let elem = items.first().map_or(TYPE_U8, type_of);
                out.push(elem | FLAG_ARRAY);
                varint(items.len() as u64, out);
                for it in items {
                    write_value(it, out);
                }
            }
        }
    }

    fn write_entry(v: &Value, out: &mut Vec<u8>) {
        match v {
            Value::Array(items) => {
                let elem = items.first().map_or(TYPE_U8, type_of);
                out.push(elem | FLAG_ARRAY);
                varint(items.len() as u64, out);
                for it in items {
                    write_value(it, out);
                }
            }
            other => {
                out.push(type_of(other));
                write_value(other, out);
            }
        }
    }

    fn write_section(s: &Section, out: &mut Vec<u8>) {
        varint(s.len() as u64, out);
        for (k, v) in s {
            out.push(k.len() as u8);
            out.extend_from_slice(k.as_bytes());
            write_entry(v, out);
        }
    }

    fn encode(s: &Section) -> Vec<u8> {
        let mut out = HEADER.to_vec();
        write_section(s, &mut out);
        out
    }

    fn section(entries: &[(&str, Value)]) -> Section {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.clone()))
            .collect()
    }

    /// `/get_o_indexes.bin` request body `{ txid: <32 bytes> }`, written out
    /// by hand from the format description: the 32-byte string length is a
    /// one-byte varint `32 << 2 = 0x80`.
    #[test]
    fn hand_written_get_o_indexes_request() {
        let mut body = HEADER.to_vec();
        body.push(1 << 2); // one entry
        body.push(4);
        body.extend_from_slice(b"txid");
        body.push(TYPE_STRING);
        body.push(0x80);
        body.extend_from_slice(&[0xab; 32]);
        let s = parse(&body).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s["txid"], Value::Bytes(vec![0xab; 32]));
    }

    /// A `/get_outs.bin` style response with an array of sections, every
    /// integer width, a double, a bool and a nested array of arrays.
    #[test]
    fn every_type_round_trips_through_the_test_writer() {
        let out = section(&[
            ("height", Value::U64(3_754_000)),
            ("key", Value::Bytes(vec![7; 32])),
            ("mask", Value::Bytes(vec![8; 32])),
            ("txid", Value::Bytes(vec![9; 32])),
            ("unlocked", Value::Bool(true)),
        ]);
        let root = section(&[
            (
                "outs",
                Value::Array(vec![Value::Section(out.clone()), Value::Section(out)]),
            ),
            ("status", Value::Bytes(b"OK".to_vec())),
            ("untrusted", Value::Bool(true)),
            ("credits", Value::U64(0)),
            ("top_hash", Value::Bytes(Vec::new())),
            ("i64", Value::I64(-5)),
            ("i32", Value::I32(-6)),
            ("i16", Value::I16(-7)),
            ("i8", Value::I8(-8)),
            ("u32", Value::U32(1 << 20)),
            ("u16", Value::U16(1 << 12)),
            ("u8", Value::U8(200)),
            ("f", Value::F64(1.5f64.to_bits())),
            (
                "matrix",
                Value::Array(vec![
                    Value::Array(vec![Value::U8(1), Value::U8(2)]),
                    Value::Array(vec![Value::U8(3)]),
                ]),
            ),
            ("empty", Value::Array(Vec::new())),
        ]);
        let bytes = encode(&root);
        let parsed = parse(&bytes).unwrap();
        assert_eq!(parsed, root);
        assert_eq!(parsed["f"].as_f64(), Some(1.5));
        assert_eq!(parsed["i8"].as_u64(), None);
        assert_eq!(parsed["u16"].as_u64(), Some(4096));
    }

    #[test]
    fn varint_widths_all_decode() {
        for n in [0u64, 63, 64, 16_383, 16_384, 1 << 29, 1 << 30, 1 << 40] {
            let mut b = Vec::new();
            varint(n, &mut b);
            let mut c = Cursor { bytes: &b, pos: 0 };
            assert_eq!(c.varint().unwrap(), n, "{n}");
            assert_eq!(c.remaining(), 0);
        }
    }

    #[test]
    fn canonical_drops_volatile_keys_and_is_order_independent() {
        let a = section(&[
            ("outs", Value::Array(vec![Value::U64(1)])),
            ("status", Value::Bytes(b"OK".to_vec())),
            ("credits", Value::U64(3)),
            ("top_hash", Value::Bytes(vec![1; 32])),
            ("untrusted", Value::Bool(false)),
        ]);
        // Same payload written by another node: different volatile values,
        // entries in another order, one extra key (a newer field).
        let mut b = section(&[
            ("untrusted", Value::Bool(true)),
            ("top_hash", Value::Bytes(vec![2; 32])),
            ("credits", Value::U64(0)),
            ("outs", Value::Array(vec![Value::U64(1)])),
        ]);
        assert_ne!(a, b);
        assert_eq!(canonical(&a, VOLATILE_KEYS), canonical(&b, VOLATILE_KEYS));
        b.insert("newer_field".into(), Value::U8(1));
        assert_ne!(
            canonical(&a, VOLATILE_KEYS),
            canonical(&b, VOLATILE_KEYS),
            "an extra non-volatile key is a real difference"
        );
        // A different payload is never canonicalised into agreement.
        let c = section(&[("outs", Value::Array(vec![Value::U64(2)]))]);
        assert_ne!(canonical(&a, VOLATILE_KEYS), canonical(&c, VOLATILE_KEYS));
    }

    #[test]
    fn bad_bodies_are_errors_not_panics() {
        assert_eq!(parse(&[]), Err(Error::Truncated));
        assert_eq!(parse(b"{\"json\":1}"), Err(Error::Signature));
        let mut v = HEADER.to_vec();
        v[8] = 2;
        assert_eq!(parse(&v), Err(Error::Version(2)));
        // Header only: the root count is missing.
        assert_eq!(parse(&HEADER), Err(Error::Truncated));
        // Empty root section, then a stray byte.
        let mut t = HEADER.to_vec();
        t.push(0);
        assert_eq!(parse(&t).unwrap(), Section::new());
        t.push(0);
        assert_eq!(parse(&t), Err(Error::Trailing));
        // Unknown type byte.
        let mut u = HEADER.to_vec();
        u.extend_from_slice(&[1 << 2, 1, b'x', 0x1f]);
        assert_eq!(parse(&u), Err(Error::UnknownType(0x1f)));
        // Array-of-arrays whose inner type is not flagged.
        let mut a = HEADER.to_vec();
        a.extend_from_slice(&[1 << 2, 1, b'x', TYPE_ARRAY, TYPE_U8, 0]);
        assert_eq!(parse(&a), Err(Error::BadArray));
        // A count far beyond the body is refused before allocating.
        let mut big = HEADER.to_vec();
        big.extend_from_slice(&[1 << 2, 1, b'x', TYPE_U64 | FLAG_ARRAY]);
        varint(u64::MAX >> 2, &mut big);
        assert_eq!(parse(&big), Err(Error::Truncated));
        // Non-UTF-8 name.
        let mut n = HEADER.to_vec();
        n.extend_from_slice(&[1 << 2, 1, 0xff, TYPE_U8, 0]);
        assert_eq!(parse(&n), Err(Error::BadName));
    }

    #[test]
    fn nesting_is_bounded() {
        // A section nested MAX_DEPTH + 2 deep: each level is one entry "s"
        // of type object.
        let mut body = HEADER.to_vec();
        for _ in 0..(MAX_DEPTH + 2) {
            body.extend_from_slice(&[1 << 2, 1, b's', TYPE_OBJECT]);
        }
        body.push(0);
        assert_eq!(parse(&body), Err(Error::TooDeep));
        // Just under the limit parses.
        let mut ok = HEADER.to_vec();
        for _ in 0..(MAX_DEPTH - 1) {
            ok.extend_from_slice(&[1 << 2, 1, b's', TYPE_OBJECT]);
        }
        ok.push(0);
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn truncation_anywhere_is_an_error() {
        let root = section(&[
            (
                "outs",
                Value::Array(vec![Value::Section(section(&[(
                    "k",
                    Value::Bytes(vec![1; 32]),
                )]))]),
            ),
            ("n", Value::U32(5)),
        ]);
        let bytes = encode(&root);
        assert!(parse(&bytes).is_ok());
        for cut in 0..bytes.len() {
            assert!(
                parse(&bytes[..cut]).is_err(),
                "prefix of {cut} bytes parsed"
            );
        }
    }
}
