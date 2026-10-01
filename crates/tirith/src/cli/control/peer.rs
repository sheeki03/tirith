//! Owner check for accepted loopback connections.
//!
//! Linux: the connecting socket's owner is read from `/proc/net/tcp` (and
//! `tcp6` for IPv4-mapped sockets), and a connection from another account is
//! dropped before it takes a connection slot or sees any response.
//! Other platforms have no stable public API that names the owner of the
//! other end of a TCP connection, so this check is not available there; the
//! per-request credential checks still apply everywhere.
use std::net::TcpStream;

/// False only when the platform shows the other end belongs to a different
/// account (or, on Linux, when no owner can be found for it).
#[cfg(target_os = "linux")]
pub(super) fn same_user(stream: &TcpStream) -> bool {
    let (Ok(std::net::SocketAddr::V4(local)), Ok(std::net::SocketAddr::V4(peer))) =
        (stream.local_addr(), stream.peer_addr())
    else {
        return false;
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    let mut readable = false;
    for (table, mapped) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Ok(text) = std::fs::read_to_string(table) else {
            continue;
        };
        readable = true;
        // The connecting socket is the row whose local end is the peer and
        // whose remote end is this service.
        if let Some(uid) = find_uid(&text, &key(peer, mapped), &key(local, mapped)) {
            return uid == me;
        }
    }
    // Without procfs this platform cannot tell; with it, a missing row
    // (for example a client that already closed) is refused.
    !readable
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
