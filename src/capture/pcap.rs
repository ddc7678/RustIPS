//! Classic pcap reader, used for deterministic replay in tests and for the
//! `--pcap` development path.
//!
//! Replay honours capture timestamps so that windowed detectors see the same
//! spacing they would have seen live.

use chrono::{DateTime, TimeZone, Utc};

use crate::capture::RawPacket;
use crate::decode::LinkType;
use crate::error::{Error, Result};

const MAGIC_USEC: u32 = 0xa1b2_c3d4;
const MAGIC_NSEC: u32 = 0xa1b2_3c4d;

pub struct PcapReader {
    data: Vec<u8>,
    offset: usize,
    endian: Endian,
    nanos: bool,
    pub link: LinkType,
    /// Timestamp of the packet most recently returned.
    pub last_ts: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl PcapReader {
    pub fn open(path: &std::path::Path) -> Result<PcapReader> {
        let data = std::fs::read(path)?;
        PcapReader::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<PcapReader> {
        if data.len() < 24 {
            return Err(Error::Capture(
                "pcap: file shorter than global header".into(),
            ));
        }
        let magic_le = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let magic_be = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let (endian, magic) = if magic_le == MAGIC_USEC || magic_le == MAGIC_NSEC {
            (Endian::Little, magic_le)
        } else if magic_be == MAGIC_USEC || magic_be == MAGIC_NSEC {
            (Endian::Big, magic_be)
        } else {
            return Err(Error::Capture(
                "pcap: unrecognised magic (not a classic pcap file)".into(),
            ));
        };
        let nanos = magic == MAGIC_NSEC;
        let network = match endian {
            Endian::Little => u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            Endian::Big => u32::from_be_bytes([data[20], data[21], data[22], data[23]]),
        };
        Ok(PcapReader {
            data,
            offset: 24,
            endian,
            nanos,
            link: LinkType::from_pcap(network & 0x0fff_ffff),
            last_ts: None,
        })
    }

    fn u32_at(&self, off: usize) -> u32 {
        let b = [
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ];
        match self.endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        }
    }

    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        if self.offset + 16 > self.data.len() {
            return Ok(None);
        }
        let sec = self.u32_at(self.offset) as i64;
        let frac = self.u32_at(self.offset + 4);
        let incl = self.u32_at(self.offset + 8) as usize;
        self.offset += 16;
        if self.offset + incl > self.data.len() {
            return Err(Error::Capture("pcap: truncated packet record".into()));
        }
        let bytes = self.data[self.offset..self.offset + incl].to_vec();
        self.offset += incl;

        let ts = if self.nanos {
            Utc.timestamp_opt(sec, frac).single()
        } else {
            Utc.timestamp_opt(sec, frac.saturating_mul(1_000)).single()
        };
        self.last_ts = ts;
        Ok(Some(RawPacket {
            data: bytes,
            ts,
            link: self.link,
        }))
    }
}

/// Build a minimal classic pcap file. Test helper, also used by the corpus
/// generator in `scripts/`.
pub fn write_pcap(packets: &[(DateTime<Utc>, Vec<u8>)], link: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC_USEC.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&link.to_le_bytes());
    for (ts, data) in packets {
        let sec = ts.timestamp() as u32;
        let usec = ts.timestamp_subsec_micros();
        out.extend_from_slice(&sec.to_le_bytes());
        out.extend_from_slice(&usec.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_packets_and_timestamps() {
        let ts = Utc.timestamp_opt(1_700_000_000, 250_000_000).unwrap();
        let bytes = write_pcap(&[(ts, vec![1, 2, 3, 4])], 1);
        let mut r = PcapReader::from_bytes(bytes).unwrap();
        assert_eq!(r.link, LinkType::Ethernet);
        let p = r.next_packet().unwrap().unwrap();
        assert_eq!(p.data, vec![1, 2, 3, 4]);
        assert_eq!(p.ts.unwrap(), ts);
        assert!(r.next_packet().unwrap().is_none());
    }

    #[test]
    fn rejects_truncated_records() {
        let mut bytes = write_pcap(&[(Utc::now(), vec![1, 2, 3, 4])], 1);
        bytes.truncate(bytes.len() - 2);
        let mut r = PcapReader::from_bytes(bytes).unwrap();
        assert!(r.next_packet().is_err());
    }
}
