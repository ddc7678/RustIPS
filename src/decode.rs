//! Packet decoding: Ethernet (with VLAN), IPv4, IPv6 and the transport
//! headers the 0.1 detectors need.
//!
//! This is deliberately bounded work: fixed-size header parsing, no
//! reassembly, no normalisation beyond skipping extension headers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::Proto;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86dd;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88a8;

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    RawIp,
    LinuxSll,
    Null,
}

impl LinkType {
    pub fn from_pcap(v: u32) -> LinkType {
        match v {
            0 => LinkType::Null,
            101 | 228 | 229 => LinkType::RawIp,
            113 => LinkType::LinuxSll,
            _ => LinkType::Ethernet,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

impl TcpInfo {
    pub fn is_syn(&self) -> bool {
        self.flags & TCP_SYN != 0
    }
    pub fn is_syn_ack(&self) -> bool {
        self.is_syn() && self.flags & TCP_ACK != 0
    }
    pub fn is_ack_only(&self) -> bool {
        self.flags & TCP_ACK != 0 && self.flags & (TCP_SYN | TCP_FIN | TCP_RST) == 0
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy)]
pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: Proto,
    pub tcp: Option<TcpInfo>,
    pub udp: Option<UdpInfo>,
    /// ICMP type, or ICMPv6 type.
    pub icmp_type: Option<u8>,
    pub payload_len: usize,
    pub payload: &'a [u8],
}

impl Packet<'_> {
    pub fn dst_port(&self) -> Option<u16> {
        match (self.tcp, self.udp) {
            (Some(t), _) => Some(t.dst_port),
            (_, Some(u)) => Some(u.dst_port),
            _ => None,
        }
    }

    pub fn is_empty_payload(&self) -> bool {
        self.payload_len == 0
    }

    /// ICMP/ICMPv6 echo request.
    pub fn is_echo_request(&self) -> bool {
        matches!(
            (self.proto, self.icmp_type),
            (Proto::Icmp, Some(8)) | (Proto::Icmpv6, Some(128))
        )
    }
}

/// Decode one captured frame. Returns `None` for anything malformed or not
/// IP; the capture path counts drops rather than panicking.
pub fn decode(link: LinkType, data: &[u8]) -> Option<Packet<'_>> {
    let ip = match link {
        LinkType::Ethernet => decode_ethernet(data)?,
        LinkType::RawIp => data,
        LinkType::LinuxSll => {
            // 16-byte cooked header, protocol in big-endian at offset 14.
            if data.len() < 16 {
                return None;
            }
            let proto = u16::from_be_bytes([data[14], data[15]]);
            match proto {
                ETH_P_IP | ETH_P_IPV6 => &data[16..],
                _ => return None,
            }
        }
        LinkType::Null => {
            // 4-byte family header; value is host-endian on the capturing host.
            if data.len() < 4 {
                return None;
            }
            let fam = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
            match fam {
                2 => &data[4..],
                24 | 28 | 30 => &data[4..],
                _ => return None,
            }
        }
    };
    decode_ip(ip)
}

fn decode_ethernet(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;
    // Up to two VLAN tags.
    for _ in 0..2 {
        if ethertype == ETH_P_8021Q || ethertype == ETH_P_8021AD {
            if data.len() < offset + 4 {
                return None;
            }
            ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            offset += 4;
        } else {
            break;
        }
    }
    match ethertype {
        ETH_P_IP | ETH_P_IPV6 => data.get(offset..),
        _ => None,
    }
}

fn decode_ip(data: &[u8]) -> Option<Packet<'_>> {
    let version = data.first()? >> 4;
    match version {
        4 => decode_ipv4(data),
        6 => decode_ipv6(data),
        _ => None,
    }
}

fn decode_ipv4(data: &[u8]) -> Option<Packet<'_>> {
    if data.len() < 20 {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let frag = u16::from_be_bytes([data[6], data[7]]);
    // Non-first fragments have no transport header.
    if frag & 0x1fff != 0 {
        return None;
    }
    let proto = data[9];
    let src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));
    let end = total_len.clamp(ihl, data.len());
    let body = &data[ihl..end];
    decode_transport(src, dst, proto, body)
}

fn decode_ipv6(data: &[u8]) -> Option<Packet<'_>> {
    if data.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let mut next = data[6];
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?));
    let mut offset = 40;
    let end = (40 + payload_len).min(data.len());

    // Walk extension headers. Fragmented packets after the first fragment are
    // ignored: no transport header is present.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if data.len() < offset + 8 {
                    return None;
                }
                let hdr_len = (data[offset + 1] as usize + 1) * 8;
                next = data[offset];
                offset += hdr_len;
            }
            44 => {
                if data.len() < offset + 8 {
                    return None;
                }
                let frag_off = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) >> 3;
                if frag_off != 0 {
                    return None;
                }
                next = data[offset];
                offset += 8;
            }
            51 => {
                if data.len() < offset + 8 {
                    return None;
                }
                let hdr_len = (data[offset + 1] as usize + 2) * 4;
                next = data[offset];
                offset += hdr_len;
            }
            _ => break,
        }
        if offset > end {
            return None;
        }
    }

    if offset > end {
        return None;
    }
    decode_transport(src, dst, next, &data[offset..end])
}

fn decode_transport(src: IpAddr, dst: IpAddr, proto: u8, body: &[u8]) -> Option<Packet<'_>> {
    match proto {
        6 => {
            if body.len() < 20 {
                return None;
            }
            let data_off = ((body[12] >> 4) as usize) * 4;
            if data_off < 20 || body.len() < data_off {
                return None;
            }
            let tcp = TcpInfo {
                src_port: u16::from_be_bytes([body[0], body[1]]),
                dst_port: u16::from_be_bytes([body[2], body[3]]),
                flags: body[13],
            };
            let payload = &body[data_off..];
            Some(Packet {
                src,
                dst,
                proto: Proto::Tcp,
                tcp: Some(tcp),
                udp: None,
                icmp_type: None,
                payload_len: payload.len(),
                payload,
            })
        }
        17 => {
            if body.len() < 8 {
                return None;
            }
            let len = u16::from_be_bytes([body[4], body[5]]) as usize;
            let end = len.clamp(8, body.len());
            let payload = &body[8..end];
            Some(Packet {
                src,
                dst,
                proto: Proto::Udp,
                tcp: None,
                udp: Some(UdpInfo {
                    src_port: u16::from_be_bytes([body[0], body[1]]),
                    dst_port: u16::from_be_bytes([body[2], body[3]]),
                }),
                icmp_type: None,
                payload_len: payload.len(),
                payload,
            })
        }
        1 => {
            if body.len() < 4 {
                return None;
            }
            Some(Packet {
                src,
                dst,
                proto: Proto::Icmp,
                tcp: None,
                udp: None,
                icmp_type: Some(body[0]),
                payload_len: body.len(),
                payload: body,
            })
        }
        58 => {
            if body.len() < 4 {
                return None;
            }
            Some(Packet {
                src,
                dst,
                proto: Proto::Icmpv6,
                tcp: None,
                udp: None,
                icmp_type: Some(body[0]),
                payload_len: body.len(),
                payload: body,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 14];
        p[12] = 0x08;
        p[13] = 0x00;
        // IPv4 header
        p.extend_from_slice(&[0x45, 0x00, 0x00, 0x28, 0, 0, 0x40, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        // TCP header
        p.extend_from_slice(&12345u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&[0; 8]); // sequence + acknowledgement
        p.push(0x50); // data offset 5 words
        p.push(flags);
        p.extend_from_slice(&[0; 6]); // window, checksum, urgent pointer
        p
    }

    #[test]
    fn decodes_ipv4_tcp_syn() {
        let frame = ipv4_tcp([10, 0, 0, 5], [10, 0, 0, 9], 22, TCP_SYN);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(pkt.src.to_string(), "10.0.0.5");
        assert_eq!(pkt.dst.to_string(), "10.0.0.9");
        assert_eq!(pkt.dst_port(), Some(22));
        assert!(pkt.tcp.unwrap().is_syn());
        assert!(pkt.is_empty_payload());
    }

    #[test]
    fn vlan_tag_is_skipped() {
        let mut frame = ipv4_tcp([10, 0, 0, 5], [10, 0, 0, 9], 80, TCP_SYN);
        // Insert a VLAN tag after the MACs.
        frame.splice(12..12, [0x81, 0x00, 0x00, 0x64]);
        let pkt = decode(LinkType::Ethernet, &frame).unwrap();
        assert_eq!(pkt.dst_port(), Some(80));
    }

    #[test]
    fn truncated_packets_are_rejected() {
        let frame = ipv4_tcp([10, 0, 0, 5], [10, 0, 0, 9], 22, TCP_SYN);
        for cut in 1..frame.len() {
            // Must never panic, and a header-only truncation must be rejected.
            let _ = decode(LinkType::Ethernet, &frame[..cut]);
        }
        assert!(decode(LinkType::Ethernet, &frame[..20]).is_none());
    }
}
