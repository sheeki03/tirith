//! Owner check for accepted loopback connections.
//!
//! Linux: the connecting socket's owner is read from `/proc/net/tcp` (and
//! `tcp6` for IPv4-mapped sockets), and a connection from another ordinary
//! account is dropped before it takes a connection slot or sees any response.
//! A root-owned client or one with no row in this kernel's tables is let
//! through: that is how a forwarded loopback connection looks (on WSL2 a
//! Windows browser arrives through a relay owned by root in NAT mode and
//! leaves no row in mirrored mode; WSL1 lists no sockets at all), and root
//! can read the service record anyway.
//! Other platforms have no stable public API that names the owner of the
//! other end of a TCP connection, so this check is not available there; the
//! per-request credential checks still apply everywhere.
use std::net::TcpStream;

/// False only when the platform shows the other end belongs to a different,
/// non-root account.
#[cfg(target_os = "linux")]
pub(super) fn same_user(stream: &TcpStream) -> bool {
    let (Ok(std::net::SocketAddr::V4(local)), Ok(std::net::SocketAddr::V4(peer))) =
        (stream.local_addr(), stream.peer_addr())
    else {
        return false;
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let tables = ["/proc/net/tcp", "/proc/net/tcp6"].map(|path| std::fs::read_to_string(path).ok());
    owner_allows(&tables, peer, local, me)
}

/// Decides from the IPv4 and IPv6 socket tables (`None` = unreadable).
#[cfg(any(test, target_os = "linux"))]
fn owner_allows(
    tables: &[Option<String>; 2],
    peer: std::net::SocketAddrV4,
    local: std::net::SocketAddrV4,
    me: u32,
) -> bool {
    for (text, mapped) in tables.iter().zip([false, true]) {
        // The connecting socket is the row whose local end is the peer and
        // whose remote end is this service.
        if let Some(uid) = text
            .as_deref()
            .and_then(|text| find_uid(text, &key(peer, mapped), &key(local, mapped)))
        {
            return uid == me || uid == 0;
        }
    }
    true
}

#[cfg(not(target_os = "linux"))]
pub(super) fn same_user(_stream: &TcpStream) -> bool {
    true
}

/// The kernel prints each 32-bit address word as a native-endian integer in
/// hex, followed by the port in hex.
#[cfg(any(test, target_os = "linux"))]
fn key(address: std::net::SocketAddrV4, mapped: bool) -> String {
    let octets: Vec<u8> = if mapped {
        address.ip().to_ipv6_mapped().octets().to_vec()
    } else {
        address.ip().octets().to_vec()
    };
    let words: String = octets
        .chunks(4)
        .map(|word| {
            format!(
                "{:08X}",
                u32::from_ne_bytes([word[0], word[1], word[2], word[3]])
            )
        })
        .collect();
    format!("{words}:{:04X}", address.port())
}

#[cfg(any(test, target_os = "linux"))]
fn find_uid(table: &str, local: &str, remote: &str) -> Option<u32> {
    table.lines().skip(1).find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() > 7
            && fields[1].eq_ignore_ascii_case(local)
            && fields[2].eq_ignore_ascii_case(remote)
        {
            fields[7].parse().ok()
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn proc_rows_are_matched_by_both_ends_and_direction() {
        let client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50000);
        let service = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
        let (client_key, service_key) = (key(client, false), key(service, false));
        let native = if cfg!(target_endian = "little") {
            "0100007F"
        } else {
            "7F000001"
        };
        assert_eq!(client_key, format!("{native}:C350"));
        let table = format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: {service_key} {client_key} 01 00000000:00000000 00:00000000 00000000  1000        0 1 1 0\n   1: {client_key} {service_key} 01 00000000:00000000 00:00000000 00000000  2000        0 2 1 0\n"
        );
        // The service's own accepted socket (uid 1000) is not the answer.
        assert_eq!(find_uid(&table, &client_key, &service_key), Some(2000));
        assert_eq!(
            find_uid(
                &table,
                &key(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1), false),
                &service_key
            ),
            None
        );
        let mapped = key(client, true);
        assert_eq!(mapped.len(), 32 + 1 + 4);
        assert!(mapped.ends_with(":C350"));
    }

    #[test]
    fn relayed_or_unlisted_loopback_peers_are_not_dropped() {
        // WSL2 NAT relays a Windows browser through /init (uid 0); mirrored
        // mode and WSL1 leave no row for the client in this kernel's tables.
        let client = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 50000);
        let service = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080);
        let header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        let row = |uid: u32| {
            Some(format!(
                "{header}   0: {} {} 01 00000000:00000000 00:00000000 00000000 {uid:>5}        0 1 1 0\n",
                key(client, false),
                key(service, false)
            ))
        };
        let empty = Some(header.to_string());
        let decide = |v4: Option<String>| owner_allows(&[v4, empty.clone()], client, service, 1000);
        assert!(decide(row(1000)), "same account");
        assert!(!decide(row(2000)), "another ordinary account is dropped");
        assert!(decide(row(0)), "root-owned relay (WSL2 NAT) is kept");
        assert!(
            decide(empty.clone()),
            "no row (WSL1, WSL2 mirrored) is kept"
        );
        assert!(
            owner_allows(&[None, None], client, service, 1000),
            "no procfs"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_connection_from_this_account_is_accepted() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        assert!(same_user(&accepted));
        drop(client);
    }
}
