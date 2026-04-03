pub mod dns;
pub mod shorturl;

pub use dns::check_dns_blocklist;
pub use shorturl::resolve_shortened_url;
