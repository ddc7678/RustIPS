//! Packet sources: live AF_PACKET sockets and classic pcap replay.
//!
//! Live capture is a plain AF_PACKET socket with a receive timeout. That is
//! enough for a single host at the 0.1 targets; a TPACKET_V3 ring is a later
//! optimisation and is isolated behind the same interface.

pub mod pcap;

use std::net::IpAddr;

use chrono::{DateTime, Utc};

use crate::decode::LinkType;
use crate::error::{Error, Result};

pub struct RawPacket {
    pub data: Vec<u8>,
    pub ts: Option<DateTime<Utc>>,
    pub link: LinkType,
}

/// Attach a classic BPF program to an AF_PACKET socket.
///
/// The kernel accepts only IPv4, IPv6 and VLAN-tagged frames, so non-IP
/// traffic costs no copy to userland. VLAN frames are accepted here and
/// unwrapped by the decoder.
fn attach_ip_filter(fd: libc::c_int, snaplen: usize) -> std::io::Result<()> {
    // stable Linux ABI: SO_ATTACH_FILTER is 26 on generic architectures.
    const SO_ATTACH_FILTER: libc::c_int = 26;
    const BPF_LD_B_H_ABS: u16 = 0x28; // BPF_LD | BPF_H | BPF_ABS
    const BPF_JMP_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K

    const ACCEPT: libc::c_uint = 0;
    let snaplen = snaplen as libc::c_uint;

    let mut prog = [
        libc::sock_filter {
            code: BPF_LD_B_H_ABS,
            jt: 0,
            jf: 0,
            k: 12,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: 0x0800,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: snaplen,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: 0x86dd,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: snaplen,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: 0x8100,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: snaplen,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: 0x88a8,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: snaplen,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: ACCEPT,
        },
    ];
    let mut fprog = libc::sock_fprog {
        len: prog.len() as libc::c_ushort,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: fprog describes a live array for the duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_ATTACH_FILTER,
            &mut fprog as *mut libc::sock_fprog as *const libc::c_void,
            std::mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct KernelStats {
    pub received: u64,
    pub dropped: u64,
}

/// Live capture on one interface.
pub struct AfPacket {
    fd: libc::c_int,
    ifname: String,
    buf: Vec<u8>,
    snaplen: usize,
}

impl AfPacket {
    pub fn open(ifname: &str, snaplen: usize, rcvbuf: usize) -> Result<AfPacket> {
        let ifindex = crate::net::interface_index(ifname)
            .map_err(|e| Error::Capture(format!("interface {ifname}: {e}")))?;

        // SAFETY: standard socket setup; errors are checked.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (libc::ETH_P_ALL as u16).to_be() as libc::c_int,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(if err.kind() == std::io::ErrorKind::PermissionDenied {
                Error::Permission(format!("opening AF_PACKET on {ifname}"))
            } else {
                Error::Capture(format!("socket(AF_PACKET) on {ifname}: {err}"))
            });
        }

        // Bind so we only see this interface.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex as i32;
        // SAFETY: addr is a valid sockaddr_ll for this family.
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(Error::Capture(format!("bind {ifname}: {err}")));
        }

        // Drop non-IP frames in the kernel.
        if let Err(e) = attach_ip_filter(fd, snaplen) {
            unsafe { libc::close(fd) };
            return Err(Error::Capture(format!(
                "attaching the IP filter on {ifname}: {e}"
            )));
        }

        if rcvbuf > 0 {
            let v = rcvbuf as libc::c_int;
            // SAFETY: setsockopt with a valid int option.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    &v as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
        }

        // A receive timeout lets the caller notice shutdown without a
        // separate wakeup pipe.
        let tv = libc::timeval {
            tv_sec: 0,
            tv_usec: 250_000,
        };
        // SAFETY: valid timeval for SO_RCVTIMEO.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const libc::timeval as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };

        Ok(AfPacket {
            fd,
            ifname: ifname.to_string(),
            buf: vec![0u8; snaplen],
            snaplen,
        })
    }

    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Blocking read with a 250 ms timeout. `Ok(None)` means timeout.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>> {
        // SAFETY: buf is snaplen bytes and the pointer/length agree.
        let n = unsafe {
            libc::recv(
                self.fd,
                self.buf.as_mut_ptr() as *mut libc::c_void,
                self.snaplen,
                0,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            return match err.kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => Ok(None),
                std::io::ErrorKind::Interrupted => Ok(None),
                _ => Err(Error::Capture(format!("recv on {}: {err}", self.ifname))),
            };
        }
        Ok(Some(RawPacket {
            data: self.buf[..n as usize].to_vec(),
            ts: None,
            link: LinkType::Ethernet,
        }))
    }

    pub fn fd(&self) -> libc::c_int {
        self.fd
    }

    /// Kernel-side counters since the socket was opened (or since the last
    /// read): frames delivered to this socket and frames dropped because the
    /// ring/socket buffer was full. Reading resets them, as documented for
    /// `PACKET_STATISTICS`.
    pub fn kernel_stats(&self) -> KernelStats {
        const PACKET_STATISTICS: libc::c_int = 6;
        let mut stats: libc::tpacket_stats = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tpacket_stats>() as libc::socklen_t;
        // SAFETY: stats is a correctly sized tpacket_stats for this option.
        let rc = unsafe {
            libc::getsockopt(
                self.fd,
                libc::SOL_PACKET,
                PACKET_STATISTICS,
                &mut stats as *mut libc::tpacket_stats as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return KernelStats::default();
        }
        KernelStats {
            received: stats.tp_packets as u64,
            dropped: stats.tp_drops as u64,
        }
    }
}

impl Drop for AfPacket {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this struct and closed once.
        unsafe { libc::close(self.fd) };
    }
}

/// Resolve `["auto"]` to the interface holding the default route.
pub fn resolve_interfaces(names: &[String]) -> Result<Vec<String>> {
    if names.len() == 1 && names[0] == "auto" {
        return crate::net::default_interface()
            .map(|n| vec![n])
            .ok_or_else(|| Error::Capture("no default route; set capture.interfaces".into()));
    }
    Ok(names.to_vec())
}

/// Enumerate non-loopback addresses. Used for the implicit allowlist and the
/// "is this packet for us" check.
pub fn local_addresses() -> Vec<IpAddr> {
    crate::net::host_addresses()
        .into_iter()
        .filter(|ip| !ip.is_loopback())
        .collect()
}

/// Attach `link` and the capture timestamp to a packet.
pub fn stamp(mut p: RawPacket, link: LinkType) -> RawPacket {
    p.link = link;
    p.ts.get_or_insert_with(Utc::now);
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_resolution_returns_an_interface_or_an_error() {
        match resolve_interfaces(&["auto".to_string()]) {
            Ok(v) => assert_eq!(v.len(), 1),
            Err(e) => assert!(e.to_string().contains("default route")),
        }
    }
}
