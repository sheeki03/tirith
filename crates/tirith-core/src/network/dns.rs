use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Known DNS-based blocklists for threat intelligence.
const DNS_BLOCKLISTS: &[(&str, &str)] = &[
    ("zen.spamhaus.org", "Spamhaus ZEN"),
    ("bl.spamcop.net", "SpamCop"),
    ("dnsbl.sorbs.net", "SORBS"),
];

/// One daemon analysis shares this budget across every attacker-controlled host.
const MAX_DNSBL_SUBJECTS: usize = 16;
const MAX_DNSBL_QUERIES: usize = 32;
const MAX_DNSBL_ADDRESSES: usize = 8;
const MAX_DNSBL_BUDGET: Duration = Duration::from_secs(8);
const MAX_RESOLVED_ADDRESSES: usize = 32;

/// A resolver whose lookup is cancelled at `deadline`.
///
/// Implementations must not leave target DNS work running after returning. The
/// production implementation drives Hickory's async socket resolver behind a
/// fixed worker and drops the lookup future at the supplied deadline; it never
/// calls the non-interruptible libc resolver.
pub trait DnsResolver {
    fn lookup_ips(&self, name: &str, deadline: Instant) -> Option<Vec<IpAddr>>;
}

struct LookupRequest {
    name: String,
    deadline: Instant,
    reply: mpsc::SyncSender<Option<Vec<IpAddr>>>,
}

/// System-configured, cancellable DNS resolver.
///
/// A single worker owns the Tokio runtime and Hickory resolver. This keeps the
/// public API synchronous for the core engine without nesting a runtime in a
/// caller that may itself be async. Each request carries its absolute deadline;
/// `tokio::time::timeout` cancels the socket lookup when that deadline wins.
pub struct SystemDnsResolver {
    requests: Option<mpsc::SyncSender<LookupRequest>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl SystemDnsResolver {
    pub fn new() -> Result<Self, String> {
        #[cfg(not(any(unix, target_os = "windows")))]
        {
            return Err("system DNS configuration is unsupported on this platform".to_string());
        }

        #[cfg(any(unix, target_os = "windows"))]
        {
            let (requests, receiver) = mpsc::sync_channel::<LookupRequest>(1);
            let (initialized_tx, initialized_rx) = mpsc::sync_channel::<Result<(), String>>(1);
            let worker = std::thread::Builder::new()
                .name("tirith-dns-resolver".to_string())
                .spawn(move || {
                    let runtime = match tokio::runtime::Builder::new_current_thread()
                        .enable_io()
                        .enable_time()
                        .build()
                    {
                        Ok(runtime) => runtime,
                        Err(error) => {
                            let _ = initialized_tx
                                .send(Err(format!("failed to create DNS runtime: {error}")));
                            return;
                        }
                    };
                    // The runtime guard has to stay alive across the constructor,
                    // which registers IO/timer drivers, so scope it to the block
                    // that builds the resolver and match on the result.
                    let created = {
                        let _entered = runtime.enter();
                        hickory_resolver::TokioAsyncResolver::tokio_from_system_conf()
                    };
                    let resolver = match created {
                        Ok(resolver) => resolver,
                        Err(error) => {
                            let _ = initialized_tx
                                .send(Err(format!("failed to load system DNS config: {error}")));
                            return;
                        }
                    };
                    if initialized_tx.send(Ok(())).is_err() {
                        return;
                    }

                    while let Ok(request) = receiver.recv() {
                        let remaining = request.deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            let _ = request.reply.send(None);
                            continue;
                        }
                        // A trailing dot makes the attacker-controlled host an FQDN,
                        // preventing resolver search-suffix expansion.
                        let fqdn = format!("{}.", request.name.trim_end_matches('.'));
                        let result = runtime.block_on(async {
                            tokio::time::timeout(remaining, resolver.lookup_ip(fqdn.as_str()))
                                .await
                                .ok()?
                                .ok()
                                .map(|lookup| lookup.iter().take(MAX_RESOLVED_ADDRESSES).collect())
                        });
                        let _ = request.reply.send(result);
                    }
                })
                .map_err(|error| format!("failed to spawn DNS resolver: {error}"))?;

            match initialized_rx.recv() {
                Ok(Ok(())) => Ok(Self {
                    requests: Some(requests),
                    worker: Some(worker),
                }),
                Ok(Err(error)) => {
                    let _ = worker.join();
                    Err(error)
                }
                Err(_) => {
                    let _ = worker.join();
                    Err("DNS resolver exited during initialization".to_string())
                }
            }
        }
    }
}

impl DnsResolver for SystemDnsResolver {
    fn lookup_ips(&self, name: &str, deadline: Instant) -> Option<Vec<IpAddr>> {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() {
            return None;
        }
        let (reply, response) = mpsc::sync_channel(1);
        self.requests
            .as_ref()?
            .try_send(LookupRequest {
                name: name.to_string(),
                deadline,
                reply,
            })
            .ok()?;
        response.recv_timeout(remaining).ok().flatten()
    }
}

impl Drop for SystemDnsResolver {
    fn drop(&mut self) {
        // Disconnecting the bounded channel lets the worker finish without a
        // sentinel. No lookup can remain in flight past its absolute deadline.
        self.requests.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Request-wide DNS accounting. Subject hosts and actual DNS queries have
/// separate caps: generated DNSBL names consume query budget but cannot consume
/// the allowance for attacker-controlled subjects.
pub struct DnsRequestBudget {
    deadline: Instant,
    max_subjects: usize,
    max_queries: usize,
    subjects: HashSet<String>,
    queries: usize,
    cache: HashMap<String, Option<Vec<IpAddr>>>,
}

impl DnsRequestBudget {
    /// Standard daemon DNSBL budget shared across the complete request.
    pub fn dnsbl() -> Self {
        Self::new(
            Instant::now() + MAX_DNSBL_BUDGET,
            MAX_DNSBL_SUBJECTS,
            MAX_DNSBL_QUERIES,
        )
    }

    /// Build a request budget with an existing deadline. Zero limits disable DNS.
    pub fn new(deadline: Instant, max_subjects: usize, max_queries: usize) -> Self {
        Self {
            deadline,
            max_subjects,
            max_queries,
            subjects: HashSet::new(),
            queries: 0,
            cache: HashMap::new(),
        }
    }

    /// Resolve one attacker-controlled subject under the shared request budget.
    /// Repeated subjects use the cached result and do not consume another query.
    pub fn resolve_subject(
        &mut self,
        resolver: &dyn DnsResolver,
        subject: &str,
    ) -> Option<Vec<IpAddr>> {
        let normalized = normalize_dns_name(subject)?;
        if !self.subjects.contains(&normalized) {
            if self.subjects.len() >= self.max_subjects {
                return None;
            }
            self.subjects.insert(normalized.clone());
        }
        self.resolve_query(resolver, &normalized)
    }

    fn resolve_query(&mut self, resolver: &dyn DnsResolver, name: &str) -> Option<Vec<IpAddr>> {
        let normalized = normalize_dns_name(name)?;
        if let Some(cached) = self.cache.get(&normalized) {
            return cached.clone();
        }
        if self.queries >= self.max_queries || Instant::now() >= self.deadline {
            return None;
        }
        self.queries += 1;
        let result = resolver.lookup_ips(&normalized, self.deadline);
        self.cache.insert(normalized, result.clone());
        result
    }
}

fn normalize_dns_name(name: &str) -> Option<String> {
    let normalized = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Backwards-compatible per-call entry point.
pub fn check_dns_blocklist(domain: &str) -> Vec<String> {
    let Ok(resolver) = SystemDnsResolver::new() else {
        return Vec::new();
    };
    let mut budget = DnsRequestBudget::dnsbl();
    check_dns_blocklist_with(domain, &resolver, &mut budget)
}

/// Check one domain while retaining a caller-owned resolver and request budget.
pub fn check_dns_blocklist_with(
    domain: &str,
    resolver: &dyn DnsResolver,
    budget: &mut DnsRequestBudget,
) -> Vec<String> {
    let mut ips: Vec<_> = match budget.resolve_subject(resolver, domain) {
        Some(ips) => ips
            .into_iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect(),
        None => return Vec::new(),
    };
    ips.sort();
    ips.dedup();

    let mut matches = Vec::new();
    for ip in ips.iter().take(MAX_DNSBL_ADDRESSES) {
        let reversed = reverse_ipv4(*ip);
        for &(zone, display_name) in DNS_BLOCKLISTS {
            let query = format!("{reversed}.{zone}");
            if budget
                .resolve_query(resolver, &query)
                .is_some_and(|addresses| addresses.iter().any(is_dnsbl_listing))
                && !matches.iter().any(|present| present == display_name)
            {
                matches.push(display_name.to_string());
            }
        }
    }
    matches
}

/// A DNSBL reports a listing with a `127.0.0.0/8` answer, but the zones also
/// answer in band with `127.255.255.0/24` for a query they refused: Spamhaus
/// returns that range for a blocked or rate-limited querier, which is the
/// normal response when the lookup comes from a public resolver. Treating any
/// non-empty answer as a listing turns "we declined your query" into a
/// High-severity blocklist finding against an innocent host.
fn is_dnsbl_listing(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 127 && !(octets[1] == 255 && octets[2] == 255)
        }
        // No zone in DNS_BLOCKLISTS publishes AAAA listings; an answer outside
        // the documented response space is not evidence of one.
        IpAddr::V6(_) => false,
    }
}

fn reverse_ipv4(ip: std::net::Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeResolver {
        answers: HashMap<String, Option<Vec<IpAddr>>>,
        calls: Mutex<Vec<(String, Instant)>>,
    }

    impl FakeResolver {
        fn with_answer(mut self, name: &str, answers: Vec<IpAddr>) -> Self {
            self.answers.insert(name.to_string(), Some(answers));
            self
        }

        fn calls(&self) -> Vec<(String, Instant)> {
            self.calls.lock().expect("calls lock").clone()
        }
    }

    impl DnsResolver for FakeResolver {
        fn lookup_ips(&self, name: &str, deadline: Instant) -> Option<Vec<IpAddr>> {
            self.calls
                .lock()
                .expect("calls lock")
                .push((name.to_string(), deadline));
            self.answers.get(name).cloned().flatten()
        }
    }

    #[test]
    fn reverse_ipv4_is_typed_and_infallible() {
        assert_eq!(
            reverse_ipv4(std::net::Ipv4Addr::new(192, 168, 1, 100)),
            "100.1.168.192"
        );
    }

    #[test]
    fn expired_budget_performs_zero_resolver_calls() {
        let resolver = FakeResolver::default();
        let mut budget = DnsRequestBudget::new(Instant::now(), 4, 4);
        assert!(budget
            .resolve_subject(&resolver, "attacker.example")
            .is_none());
        assert!(resolver.calls().is_empty());
    }

    #[test]
    fn a_reserved_dnsbl_answer_is_not_read_as_a_listing() {
        // Spamhaus answers `127.255.255.x` when it refuses the query — a blocked
        // or rate-limited querier, which is the normal reply when the lookup
        // comes from a public resolver. That must not become a blocklist hit.
        let deadline = Instant::now() + Duration::from_secs(1);
        let refused = FakeResolver::default()
            .with_answer("host.example", vec!["192.0.2.10".parse().unwrap()])
            .with_answer(
                "10.2.0.192.zen.spamhaus.org",
                vec!["127.255.255.254".parse().unwrap()],
            );
        let mut budget = DnsRequestBudget::new(deadline, 4, 8);
        assert!(
            check_dns_blocklist_with("host.example", &refused, &mut budget).is_empty(),
            "an in-band refusal code is not evidence that the host is listed"
        );

        // A real listing code inside 127.0.0.0/8 still reports.
        let listed = FakeResolver::default()
            .with_answer("host.example", vec!["192.0.2.10".parse().unwrap()])
            .with_answer(
                "10.2.0.192.zen.spamhaus.org",
                vec!["127.0.0.2".parse().unwrap()],
            );
        let mut budget = DnsRequestBudget::new(deadline, 4, 8);
        assert_eq!(
            check_dns_blocklist_with("host.example", &listed, &mut budget),
            vec!["Spamhaus ZEN".to_string()]
        );
    }

    #[test]
    fn shared_budget_caps_subjects_and_total_queries() {
        let resolver = FakeResolver::default()
            .with_answer("one.example", vec!["192.0.2.1".parse().unwrap()])
            .with_answer("two.example", vec!["192.0.2.2".parse().unwrap()])
            .with_answer("three.example", vec!["192.0.2.3".parse().unwrap()]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut budget = DnsRequestBudget::new(deadline, 2, 3);

        let _ = check_dns_blocklist_with("one.example", &resolver, &mut budget);
        let _ = check_dns_blocklist_with("two.example", &resolver, &mut budget);
        let _ = check_dns_blocklist_with("three.example", &resolver, &mut budget);

        let calls = resolver.calls();
        assert_eq!(calls.len(), 3, "one subject plus two DNSBL queries");
        assert!(calls
            .iter()
            .all(|(_, call_deadline)| *call_deadline == deadline));
        assert!(!calls.iter().any(|(name, _)| name == "two.example"));
        assert!(!calls.iter().any(|(name, _)| name == "three.example"));
    }

    #[test]
    fn repeated_subject_uses_cached_dns_result() {
        let resolver = FakeResolver::default()
            .with_answer("repeat.example", vec!["192.0.2.1".parse().unwrap()]);
        let mut budget = DnsRequestBudget::new(Instant::now() + Duration::from_secs(1), 1, 4);

        assert!(budget
            .resolve_subject(&resolver, "REPEAT.example.")
            .is_some());
        assert!(budget
            .resolve_subject(&resolver, "repeat.example")
            .is_some());
        assert_eq!(resolver.calls().len(), 1);
    }
}
