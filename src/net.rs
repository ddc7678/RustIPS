//! Address helpers: CIDR parsing/matching and the implicit allowlist set.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let addr: IpAddr = a.parse().map_err(|_| format!("invalid address {a:?}"))?;
                let prefix: u8 = p.parse().map_err(|_| format!("invalid prefix {p:?}"))?;
                (addr, prefix)
            }
            None => {
                let addr: IpAddr = s.parse().map_err(|_| format!("invalid address {s:?}"))?;
                let prefix = if addr.is_ipv4() { 32 } else { 128 };
                (addr, prefix)
            }
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("prefix /{prefix} exceeds /{max} for {addr}"));
        }
        Ok(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            // A v4 CIDR does not match a v6 address; callers normally
            // normalise v4-mapped addresses first.
            _ => false,
        }
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Normalise IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to plain IPv4 so that
/// allowlist entries and blocks behave identically regardless of socket type.
pub fn normalise(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Addresses that must never be blocked (FR-154). This is the part of the
/// allowlist that cannot be removed: loopback, link-local, unspecified,
/// RFC1918, IPv6 unique-local, and the host's own addresses.
pub fn is_implicitly_allowed(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
        }
    }
}

/// Enumerate the host's own addresses with `getifaddrs(3)`.
pub fn host_addresses() -> Vec<IpAddr> {
    use std::ffi::CStr;

    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a linked list that we free below.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: cur is a valid node of the list returned by getifaddrs.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr points to a sockaddr of the family it reports.
            let family = unsafe { (*ifa.ifa_addr).sa_family as i32 };
            let ip = match family {
                libc::AF_INET => {
                    // SAFETY: family is AF_INET.
                    let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))))
                }
                libc::AF_INET6 => {
                    // SAFETY: family is AF_INET6.
                    let sa = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
                }
                _ => None,
            };
            if let Some(ip) = ip {
                out.push(ip);
            }
            // Touch ifa_name so the name is available for future diagnostics.
            if !ifa.ifa_name.is_null() {
                // SAFETY: ifa_name is a NUL-terminated string owned by the list.
                let _name = unsafe { CStr::from_ptr(ifa.ifa_name) };
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: list was allocated by getifaddrs.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

/// Interface index by name, using `if_nametoindex(3)`.
pub fn interface_index(name: &str) -> std::io::Result<u32> {
    let cname = std::ffi::CString::new(name).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "interface name contains a NUL byte",
        )
    })?;
    // SAFETY: cname is a valid NUL-terminated string for the duration of the call.
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(idx)
    }
}

/// Name of the interface holding the default route, from `/proc/net/route`.
pub fn default_interface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_interface(&text)
}

/// Pick the lowest-metric default route. `/proc/net/route` is not guaranteed to
/// list routes in metric order, and a bridged interface can appear after the
/// NAT interface, so relying on the first line is not enough.
fn parse_default_interface(text: &str) -> Option<String> {
    let mut best: Option<(u32, bool, String)> = None;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 || cols[1] != "00000000" {
            continue;
        }
        let metric = cols[6].parse::<u32>().unwrap_or(u32::MAX);
        // Prefer a real gateway when metrics tie; a device-only default route
        // is still a valid fallback.
        let no_gateway = cols[2] == "00000000";
        let candidate = (metric, no_gateway, cols[0].to_string());
        let replace = match &best {
            Some((m, ng, _)) => (candidate.0, candidate.1) < (*m, *ng),
            None => true,
        };
        if replace {
            best = Some(candidate);
        }
    }
    best.map(|(_, _, iface)| iface)
}

pub fn parse_ip(s: &str) -> crate::error::Result<IpAddr> {
    s.trim()
        .parse::<IpAddr>()
        .map(normalise)
        .map_err(|_| crate::error::Error::invalid(format!("invalid IP address {s:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matches() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(!c.contains("11.1.2.3".parse().unwrap()));
        let c6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c6.contains("2001:db8::1".parse().unwrap()));
        assert!(!c6.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn implicit_set_covers_private_and_loopback() {
        assert!(is_implicitly_allowed("127.0.0.1".parse().unwrap()));
        assert!(is_implicitly_allowed("192.168.1.5".parse().unwrap()));
        assert!(is_implicitly_allowed("fe80::1".parse().unwrap()));
        assert!(!is_implicitly_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn default_route_prefers_the_lowest_metric() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
enp0s2\t00000000\t0202000A\t0003\t0\t0\t200\t00000000\t0\t0\t0\n\
enp0s4\t00000000\t010CA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
enp0s2\t0002000A\t00000000\t0001\t0\t0\t200\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_default_interface(table).as_deref(), Some("enp0s4"));
    }

    #[test]
    fn default_route_prefers_a_gateway_on_equal_metrics() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
enp0s2\t00000000\t00000000\t0001\t0\t0\t100\t00000000\t0\t0\t0\n\
enp0s4\t00000000\t010CA8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";
        assert_eq!(parse_default_interface(table).as_deref(), Some("enp0s4"));
    }
}
