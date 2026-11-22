//! Disposition-only GeoIP/ASN enrichment (FR-160…169).
//!
//! The runtime format is a compact, sorted range index built from the
//! `ip-location-db` CSV releases. It is loaded into memory as a single byte
//! buffer and searched without per-record allocation: a v4 record is 10 bytes
//! (country) or 12 bytes (ASN), a v6 record is 34 or 36 bytes. The shipped
//! country + ASN indexes occupy roughly 23 MB, under the FR-162 budget.
//!
//! Geo data never feeds a detector. Only `record_detection` consults it, after
//! a real detection has happened, to evaluate disposition rules.

pub mod update;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAGIC: &[u8; 8] = b"RIPSGEO1";
const HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeoKind {
    Country,
    Asn,
}

impl GeoKind {
    fn code(self) -> u8 {
        match self {
            GeoKind::Country => 1,
            GeoKind::Asn => 2,
        }
    }

    fn from_code(code: u8) -> Option<GeoKind> {
        match code {
            1 => Some(GeoKind::Country),
            2 => Some(GeoKind::Asn),
            _ => None,
        }
    }

    fn value_len(self) -> usize {
        match self {
            GeoKind::Country => 2,
            GeoKind::Asn => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GeoKind::Country => "country",
            GeoKind::Asn => "asn",
        }
    }

    pub fn filename(self) -> &'static str {
        match self {
            GeoKind::Country => "country.bin",
            GeoKind::Asn => "asn.bin",
        }
    }
}

/// A loaded index. The byte buffer is immutable after construction.
#[derive(Debug)]
pub struct GeoIndex {
    kind: GeoKind,
    value_len: usize,
    v4_count: usize,
    v6_count: usize,
    bytes: Vec<u8>,
    sha256: String,
}

#[derive(Debug, Clone)]
pub struct BuildStats {
    pub kind: GeoKind,
    pub v4: usize,
    pub v6: usize,
    pub bytes: u64,
    pub sha256: String,
    pub built_at: DateTime<Utc>,
}

impl GeoIndex {
    pub fn open(path: &Path, expected: GeoKind) -> Result<GeoIndex> {
        let bytes = std::fs::read(path)?;
        if bytes.len() < HEADER_LEN || &bytes[..8] != MAGIC {
            return Err(Error::Config(format!(
                "{} is not a RustIPS geo index",
                path.display()
            )));
        }
        let kind = GeoKind::from_code(bytes[8])
            .ok_or_else(|| Error::Config(format!("{} has an unknown geo kind", path.display())))?;
        if kind != expected {
            return Err(Error::Config(format!(
                "{} holds {} data, expected {}",
                path.display(),
                kind.as_str(),
                expected.as_str()
            )));
        }
        let value_len = bytes[9] as usize;
        if value_len != kind.value_len() {
            return Err(Error::Config(format!(
                "{} has value width {value_len}, expected {}",
                path.display(),
                kind.value_len()
            )));
        }
        let v4_count = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
        let v6_count = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
        let v4_stride = 8 + value_len;
        let v6_stride = 32 + value_len;
        let expected_len = HEADER_LEN + v4_count * v4_stride + v6_count * v6_stride;
        if bytes.len() != expected_len {
            return Err(Error::Config(format!(
                "{} is {} bytes, expected {expected_len}",
                path.display(),
                bytes.len()
            )));
        }
        let sha256 = to_hex(&sha256(&bytes));
        Ok(GeoIndex {
            kind,
            value_len,
            v4_count,
            v6_count,
            bytes,
            sha256,
        })
    }

    pub fn kind(&self) -> GeoKind {
        self.kind
    }

    pub fn counts(&self) -> (usize, usize) {
        (self.v4_count, self.v6_count)
    }

    pub fn byte_len(&self) -> usize {
        self.bytes.len()
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn lookup(&self, ip: IpAddr) -> Option<u32> {
        match ip {
            IpAddr::V4(ip) => self.lookup_v4(u32::from(ip)),
            IpAddr::V6(ip) => self.lookup_v6(u128::from(ip)),
        }
    }

    fn lookup_v4(&self, ip: u32) -> Option<u32> {
        if self.v4_count == 0 {
            return None;
        }
        let stride = 8 + self.value_len;
        let mut lo = 0usize;
        let mut hi = self.v4_count;
        // Find the last record whose start <= ip.
        while lo < hi {
            let mid = (lo + hi) / 2;
            let start = self.read_u32(HEADER_LEN + mid * stride);
            if start <= ip {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let index = lo - 1;
        let offset = HEADER_LEN + index * stride;
        let end = self.read_u32(offset + 4);
        if ip > end {
            return None;
        }
        Some(self.read_value(offset + 8))
    }

    fn lookup_v6(&self, ip: u128) -> Option<u32> {
        if self.v6_count == 0 {
            return None;
        }
        let base = HEADER_LEN + self.v4_count * (8 + self.value_len);
        let stride = 32 + self.value_len;
        let mut lo = 0usize;
        let mut hi = self.v6_count;
        while lo < hi {
            let mid = (lo + hi) / 2;
            let start = self.read_u128(base + mid * stride);
            if start <= ip {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if lo == 0 {
            return None;
        }
        let index = lo - 1;
        let offset = base + index * stride;
        let end = self.read_u128(offset + 16);
        if ip > end {
            return None;
        }
        Some(self.read_value(offset + 32))
    }

    fn read_u32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap())
    }

    fn read_u128(&self, offset: usize) -> u128 {
        u128::from_le_bytes(self.bytes[offset..offset + 16].try_into().unwrap())
    }

    fn read_value(&self, offset: usize) -> u32 {
        match self.value_len {
            2 => u16::from_le_bytes(self.bytes[offset..offset + 2].try_into().unwrap()) as u32,
            4 => u32::from_le_bytes(self.bytes[offset..offset + 4].try_into().unwrap()),
            _ => 0,
        }
    }
}

/// Lookup result attached to a detection for disposition rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub asn: Option<u32>,
}

impl GeoInfo {
    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.asn.is_none()
    }
}

#[derive(Debug, Default)]
pub struct GeoData {
    pub country: Option<Arc<GeoIndex>>,
    pub asn: Option<Arc<GeoIndex>>,
}

impl GeoData {
    pub fn lookup(&self, ip: IpAddr) -> GeoInfo {
        let country = self
            .country
            .as_ref()
            .and_then(|index| index.lookup(ip))
            .and_then(code_to_country);
        let asn = self.asn.as_ref().and_then(|index| index.lookup(ip));
        GeoInfo { country, asn }
    }

    pub fn is_empty(&self) -> bool {
        self.country.is_none() && self.asn.is_none()
    }
}

pub type GeoHandle = Arc<RwLock<GeoData>>;

pub fn empty_handle() -> GeoHandle {
    Arc::new(RwLock::new(GeoData::default()))
}

/// Load whichever indexes are present; a missing or corrupt index is reported
/// and leaves geo rules disabled for that attribute (FR-167).
pub fn load_from_dir(state_dir: &Path) -> GeoData {
    let dir = state_dir.join("geo");
    let country = match GeoIndex::open(&dir.join(GeoKind::Country.filename()), GeoKind::Country) {
        Ok(index) => Some(Arc::new(index)),
        Err(e) => {
            if !matches!(e, Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound) {
                tracing::warn!("cannot load the country geo index: {e}");
            }
            None
        }
    };
    let asn = match GeoIndex::open(&dir.join(GeoKind::Asn.filename()), GeoKind::Asn) {
        Ok(index) => Some(Arc::new(index)),
        Err(e) => {
            if !matches!(e, Error::Io(ref io) if io.kind() == std::io::ErrorKind::NotFound) {
                tracing::warn!("cannot load the ASN geo index: {e}");
            }
            None
        }
    };
    GeoData { country, asn }
}

/// Install a freshly built index, keeping the previous generation.
pub fn install(state_dir: &Path, kind: GeoKind, temp: &Path) -> Result<PathBuf> {
    let dir = state_dir.join("geo");
    std::fs::create_dir_all(&dir)?;
    let final_path = dir.join(kind.filename());
    let prev = dir.join(format!("{}.prev", kind.filename()));
    if final_path.exists() {
        let _ = std::fs::remove_file(&prev);
        std::fs::rename(&final_path, &prev)?;
    }
    std::fs::rename(temp, &final_path)?;
    Ok(final_path)
}

/// Build an index from the v4 and v6 CSV files. Records must be sorted and
/// non-overlapping; a malformed file is rejected before it can replace a good
/// index (FR-164).
pub fn build_index(
    kind: GeoKind,
    v4_path: &Path,
    v6_path: &Path,
    out_path: &Path,
) -> Result<BuildStats> {
    let v4 = parse_csv(v4_path, kind, true)?;
    let v6 = parse_csv(v6_path, kind, false)?;
    let value_len = kind.value_len();
    let total = HEADER_LEN + v4.len() * (8 + value_len) + v6.len() * (32 + value_len);
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(MAGIC);
    bytes.push(kind.code());
    bytes.push(value_len as u8);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&(v4.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(v6.len() as u32).to_le_bytes());
    for record in &v4 {
        bytes.extend_from_slice(&(record.start as u32).to_le_bytes());
        bytes.extend_from_slice(&(record.end as u32).to_le_bytes());
        bytes.extend_from_slice(&record.value.to_le_bytes()[..value_len]);
    }
    for record in &v6 {
        bytes.extend_from_slice(&record.start.to_le_bytes());
        bytes.extend_from_slice(&record.end.to_le_bytes());
        bytes.extend_from_slice(&record.value.to_le_bytes()[..value_len]);
    }
    std::fs::write(out_path, &bytes)?;
    Ok(BuildStats {
        kind,
        v4: v4.len(),
        v6: v6.len(),
        bytes: bytes.len() as u64,
        sha256: to_hex(&sha256(&bytes)),
        built_at: Utc::now(),
    })
}

struct Record {
    start: u128,
    end: u128,
    value: u32,
}

fn parse_csv(path: &Path, kind: GeoKind, v4: bool) -> Result<Vec<Record>> {
    use std::io::BufRead;
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::with_capacity(256 * 1024, file);
    let mut out = Vec::new();
    let mut previous_end: Option<u128> = None;
    for (line_no, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split(',');
        let start_text = fields.next().unwrap_or("").trim();
        let end_text = fields.next().unwrap_or("").trim();
        let value_text = fields.next().unwrap_or("").trim();
        let (start, end) = if v4 {
            let start: Ipv4Addr = start_text.parse().map_err(|_| {
                Error::Config(format!(
                    "{}:{}: invalid IPv4 start",
                    path.display(),
                    line_no + 1
                ))
            })?;
            let end: Ipv4Addr = end_text.parse().map_err(|_| {
                Error::Config(format!(
                    "{}:{}: invalid IPv4 end",
                    path.display(),
                    line_no + 1
                ))
            })?;
            (u32::from(start) as u128, u32::from(end) as u128)
        } else {
            let start: Ipv6Addr = start_text.parse().map_err(|_| {
                Error::Config(format!(
                    "{}:{}: invalid IPv6 start",
                    path.display(),
                    line_no + 1
                ))
            })?;
            let end: Ipv6Addr = end_text.parse().map_err(|_| {
                Error::Config(format!(
                    "{}:{}: invalid IPv6 end",
                    path.display(),
                    line_no + 1
                ))
            })?;
            (u128::from(start), u128::from(end))
        };
        if start > end {
            return Err(Error::Config(format!(
                "{}:{}: range start is after end",
                path.display(),
                line_no + 1
            )));
        }
        if let Some(previous) = previous_end {
            if start <= previous {
                return Err(Error::Config(format!(
                    "{}:{}: overlapping or unsorted range",
                    path.display(),
                    line_no + 1
                )));
            }
        }
        previous_end = Some(end);
        let value = match kind {
            GeoKind::Country => {
                let bytes = value_text.as_bytes();
                if bytes.len() != 2 || !bytes.iter().all(|b| b.is_ascii_uppercase()) {
                    return Err(Error::Config(format!(
                        "{}:{}: invalid country code {value_text:?}",
                        path.display(),
                        line_no + 1
                    )));
                }
                ((bytes[0] as u32) << 8) | bytes[1] as u32
            }
            GeoKind::Asn => {
                let text = value_text.strip_prefix("AS").unwrap_or(value_text);
                text.parse::<u32>().map_err(|_| {
                    Error::Config(format!(
                        "{}:{}: invalid ASN {value_text:?}",
                        path.display(),
                        line_no + 1
                    ))
                })?
            }
        };
        out.push(Record { start, end, value });
    }
    Ok(out)
}

fn code_to_country(value: u32) -> Option<String> {
    let bytes = [(value >> 8) as u8, value as u8];
    if bytes.iter().all(|b| b.is_ascii_uppercase()) {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    } else {
        None
    }
}

/// Metadata kept in the `geo.status` setting and shown in the UI.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoStatus {
    pub last_check: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    pub next_check: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub country: Option<GeoIndexStatus>,
    pub asn: Option<GeoIndexStatus>,
    /// SHA-256 of each source CSV from the last successful download. Used to
    /// skip the CSVs entirely when the published checksums are unchanged.
    #[serde(default)]
    pub sources: std::collections::BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIndexStatus {
    pub sha256: String,
    pub v4: usize,
    pub v6: usize,
    pub bytes: u64,
    pub loaded_at: DateTime<Utc>,
}

pub fn index_status(index: &GeoIndex, loaded_at: DateTime<Utc>) -> GeoIndexStatus {
    let (v4, v6) = index.counts();
    GeoIndexStatus {
        sha256: index.sha256().to_string(),
        v4,
        v6,
        bytes: index.byte_len() as u64,
        loaded_at,
    }
}

// ------------------------------------------------------------------------ sha256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Pure-Rust SHA-256 used to verify downloaded CSVs (FR-164). This is not a
/// general-purpose crypto API; it only needs to match the published checksum.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn csv(dir: &Path, name: &str, rows: &[&str]) -> PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        for row in rows {
            writeln!(file, "{row}").unwrap();
        }
        path
    }

    #[test]
    fn builds_and_looks_up_country_index() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-geo-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let v4 = csv(
            &dir,
            "v4.csv",
            &[
                "1.0.0.0,1.0.0.255,AU",
                "1.0.1.0,1.0.3.255,CN",
                "203.0.113.0,203.0.113.255,US",
            ],
        );
        let v6 = csv(
            &dir,
            "v6.csv",
            &[
                "2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP",
                "2001:db8::,2001:db8:ffff:ffff:ffff:ffff:ffff:ffff,GB",
            ],
        );
        let out = dir.join("country.bin");
        let stats = build_index(GeoKind::Country, &v4, &v6, &out).unwrap();
        assert_eq!(stats.v4, 3);
        assert_eq!(stats.v6, 2);
        let index = GeoIndex::open(&out, GeoKind::Country).unwrap();
        assert_eq!(
            index.lookup("1.0.1.5".parse().unwrap()),
            Some((b'C' as u32) << 8 | b'N' as u32)
        );
        assert_eq!(index.lookup("1.0.4.1".parse().unwrap()), None);
        assert_eq!(
            index.lookup("2001:db8::1".parse().unwrap()),
            Some((b'G' as u32) << 8 | b'B' as u32)
        );
        assert_eq!(index.lookup("2001:4860::1".parse().unwrap()), None);

        let data = GeoData {
            country: Some(std::sync::Arc::new(index)),
            asn: None,
        };
        let info = data.lookup("203.0.113.9".parse().unwrap());
        assert_eq!(info.country.as_deref(), Some("US"));
        assert_eq!(info.asn, None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn builds_asn_index_and_rejects_overlaps() {
        let dir = std::env::temp_dir().join(format!(
            "rustips-geo-asn-{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let v4 = csv(
            &dir,
            "v4.csv",
            &[
                "1.0.0.0,1.0.0.255,13335,\"Cloudflare\"",
                "1.0.1.0,1.0.3.255,38803,Org",
            ],
        );
        let v6 = csv(
            &dir,
            "v6.csv",
            &["2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,2500,Org"],
        );
        let out = dir.join("asn.bin");
        let stats = build_index(GeoKind::Asn, &v4, &v6, &out).unwrap();
        assert_eq!(stats.v4, 2);
        let index = GeoIndex::open(&out, GeoKind::Asn).unwrap();
        assert_eq!(index.lookup("1.0.0.1".parse().unwrap()), Some(13335));
        assert_eq!(index.lookup("1.0.2.1".parse().unwrap()), Some(38803));
        assert_eq!(index.lookup("1.0.4.1".parse().unwrap()), None);

        let bad = csv(&dir, "bad.csv", &["1.0.0.0,1.0.5.0,1", "1.0.5.0,1.0.6.0,2"]);
        let bad6 = csv(&dir, "bad6.csv", &[]);
        assert!(build_index(GeoKind::Asn, &bad, &bad6, &dir.join("bad.bin")).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
