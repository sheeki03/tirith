//! Bounded authenticated transport for a pinned optional policy authority.
use crate::policy_team::*;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::{de::DeserializeOwned, Serialize};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Explicit connection-local transport choices. A pinned address is never
/// learned from a server response, repository policy, or ambient proxy.
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointOptions {
    #[serde(default)]
    pub pinned_addresses: Vec<IpAddr>,
    #[serde(default)]
    pub additional_ca_pem: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityBinding {
    pub schema_version: u32,
    pub base_url: String,
    pub authority_id: Id,
    pub policy_id: Id,
    #[serde(default)]
    pub transport: EndpointOptions,
}

pub struct TeamClient {
    http: Client,
    base: url::Url,
    credential: HeaderValue,
    binding: AuthorityBinding,
}

/// A recent successful publisher authentication, retained only in memory.
/// Publication still authenticates again and enforces the server revision CAS.
pub struct PublisherObservation {
    pub(crate) observed_unix_ms: u64,
}

fn clock_ms() -> Result<u64, ErrorCode> {
    chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .map_err(|_| ErrorCode::InvalidResponse)
}
fn endpoint(raw: &str, options: &EndpointOptions) -> Result<url::Url, ErrorCode> {
    if raw.is_empty() || raw.len() > 2048 || raw.chars().any(char::is_control) {
        return Err(ErrorCode::InvalidRequest);
    }
    let parsed = url::Url::parse(raw).map_err(|_| ErrorCode::InvalidRequest)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host().is_none()
        || parsed.port() == Some(0)
        || parsed
            .host_str()
            .is_some_and(crate::url_validate::is_cloud_metadata_host)
    {
        return Err(ErrorCode::InvalidRequest);
    }
    if options.pinned_addresses.is_empty() {
        crate::url_validate::validate_server_url(parsed.as_str())
            .map_err(|_| ErrorCode::InvalidRequest)?;
    } else {
        let unique: std::collections::BTreeSet<_> = options.pinned_addresses.iter().collect();
        if unique.len() != options.pinned_addresses.len()
            || unique.len() > 8
            || unique
                .iter()
                .any(|address| !allowed_pinned_address(**address))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let literal = match parsed.host() {
            Some(url::Host::Ipv4(address)) => Some(IpAddr::V4(address)),
            Some(url::Host::Ipv6(address)) => Some(IpAddr::V6(address)),
            _ => None,
        };
        if literal.is_some_and(|address| !options.pinned_addresses.contains(&address)) {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    Ok(parsed)
}
fn allowed_pinned_address(address: IpAddr) -> bool {
    use crate::url_validate::AddressScope;
    !matches!(address, IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some())
        && matches!(
            crate::url_validate::classify_ip(&address),
            AddressScope::Global | AddressScope::PrivateUse | AddressScope::Loopback
        )
}
fn credential(token: &str) -> Result<HeaderValue, ErrorCode> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ErrorCode::Unauthorized);
    }
    let mut header =
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| ErrorCode::Unauthorized)?;
    header.set_sensitive(true);
    Ok(header)
}
fn builder(
    base: &url::Url,
    options: &EndpointOptions,
) -> Result<reqwest::blocking::ClientBuilder, ErrorCode> {
    let mut builder = if options.pinned_addresses.is_empty() {
        crate::ssrf_guard::server_client_builder()
    } else {
        let addresses: Vec<_> = options
            .pinned_addresses
            .iter()
            .map(|address| SocketAddr::new(*address, 0))
            .collect();
        reqwest::blocking::Client::builder()
            .no_proxy()
            .resolve_to_addrs(
                base.host_str().ok_or(ErrorCode::InvalidRequest)?,
                &addresses,
            )
    };
    if let Some(pem) = &options.additional_ca_pem {
        if pem.is_empty() || pem.len() > 64 * 1024 {
            return Err(ErrorCode::InvalidRequest);
        }
        let certificate = reqwest::Certificate::from_pem(pem.as_bytes())
            .map_err(|_| ErrorCode::InvalidRequest)?;
        builder = builder.add_root_certificate(certificate);
    }
    Ok(builder
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10)))
}
fn route(base: &url::Url, suffix: &str) -> Result<url::Url, ErrorCode> {
    url::Url::parse(&format!(
        "{}{}",
        base.as_str().trim_end_matches('/'),
        suffix
    ))
    .map_err(|_| ErrorCode::InvalidRequest)
}
fn decode<T: DeserializeOwned>(response: Response, mutation: bool) -> Result<T, ErrorCode> {
    decode_inner(response, mutation).map_err(|error| {
        if mutation
            && matches!(
                error,
                ErrorCode::InvalidResponse | ErrorCode::UnsupportedContract
            )
        {
            ErrorCode::OutcomeUnknown
        } else {
            error
        }
    })
}
fn decode_inner<T: DeserializeOwned>(response: Response, mutation: bool) -> Result<T, ErrorCode> {
    let status = response.status();
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ErrorCode::InvalidResponse);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            if mutation {
                ErrorCode::OutcomeUnknown
            } else {
                ErrorCode::TransportUnavailable
            }
        })?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ErrorCode::InvalidResponse);
    }
    if status.as_u16() == 200 || status.as_u16() == 201 {
        return serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidResponse);
    }
    if mutation && matches!(status.as_u16(), 408 | 504) {
        return Err(ErrorCode::OutcomeUnknown);
    }
    let error: ErrorResponse =
        serde_json::from_slice(&bytes).map_err(|_| ErrorCode::InvalidResponse)?;
    schema(error.schema_version)?;
    Err(error.error)
}

impl TeamClient {
    pub fn discover(base_url: &str, token: &str) -> Result<(Self, Capabilities), ErrorCode> {
        Self::discover_with_options(base_url, token, EndpointOptions::default())
    }
    pub fn discover_with_options(
        base_url: &str,
        token: &str,
        transport: EndpointOptions,
    ) -> Result<(Self, Capabilities), ErrorCode> {
        let base = endpoint(base_url, &transport)?;
        let credential = credential(token)?;
        let http = builder(&base, &transport)?
            .build()
            .map_err(|_| ErrorCode::TransportUnavailable)?;
        let response = http
            .get(route(&base, "/api/policy/v1/capabilities")?)
            .header(AUTHORIZATION, credential.clone())
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| ErrorCode::TransportUnavailable)?;
        let capabilities: Capabilities = decode(response, false)?;
        capabilities.validate(clock_ms()?)?;
        let binding = AuthorityBinding {
            schema_version: SCHEMA_VERSION,
            base_url: base.as_str().trim_end_matches('/').into(),
            authority_id: capabilities.authority_id.clone(),
            policy_id: capabilities.policy_id.clone(),
            transport,
        };
        Ok((
            Self {
                http,
                base,
                credential,
                binding,
            },
            capabilities,
        ))
    }
    pub fn connect(binding: AuthorityBinding, token: &str) -> Result<Self, ErrorCode> {
        schema(binding.schema_version)?;
        let (client, capabilities) =
            Self::discover_with_options(&binding.base_url, token, binding.transport.clone())?;
        if client.binding.base_url != binding.base_url.trim_end_matches('/')
            || capabilities.authority_id != binding.authority_id
            || capabilities.policy_id != binding.policy_id
        {
            return Err(ErrorCode::AuthorityChanged);
        }
        Ok(client)
    }
    pub fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }
    pub fn publisher_observation(&self) -> Result<PublisherObservation, ErrorCode> {
        if self.capabilities()?.role != Role::Publisher {
            return Err(ErrorCode::Forbidden);
        }
        Ok(PublisherObservation {
            observed_unix_ms: clock_ms()?,
        })
    }
    pub fn capabilities(&self) -> Result<Capabilities, ErrorCode> {
        let value: Capabilities = self.get("/api/policy/v1/capabilities")?;
        self.identity(&value.authority_id, &value.policy_id)?;
        value.validate(clock_ms()?)?;
        Ok(value)
    }
    /// Read the current server-owned sequence immediately before constructing
    /// a report. Rotation of a credential must not reset client history.
    pub fn report_position(&self) -> Result<(Id, u64), ErrorCode> {
        let value = self.capabilities()?;
        if value.role != Role::Client {
            return Err(ErrorCode::Forbidden);
        }
        Ok((
            value.client_id.ok_or(ErrorCode::InvalidResponse)?,
            value
                .client_report_sequence
                .ok_or(ErrorCode::InvalidResponse)?,
        ))
    }
    fn identity(&self, authority: &Id, policy: &Id) -> Result<(), ErrorCode> {
        if authority == &self.binding.authority_id && policy == &self.binding.policy_id {
            Ok(())
        } else {
            Err(ErrorCode::AuthorityChanged)
        }
    }
    fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ErrorCode> {
        let response = self
            .http
            .get(route(&self.base, path)?)
            .header(AUTHORIZATION, self.credential.clone())
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|_| ErrorCode::TransportUnavailable)?;
        decode(response, false)
    }
    fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        value: &impl Serialize,
    ) -> Result<T, ErrorCode> {
        self.post_body(path, value, true)
    }
    fn post_body<T: DeserializeOwned>(
        &self,
        path: &str,
        value: &impl Serialize,
        mutation: bool,
    ) -> Result<T, ErrorCode> {
        let body = serde_json::to_vec(value).map_err(|_| ErrorCode::InvalidRequest)?;
        if body.len() > MAX_REQUEST_BYTES {
            return Err(ErrorCode::InvalidRequest);
        }
        let response = self
            .http
            .post(route(&self.base, path)?)
            .header(AUTHORIZATION, self.credential.clone())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .map_err(|_| {
                if mutation {
                    ErrorCode::OutcomeUnknown
                } else {
                    ErrorCode::TransportUnavailable
                }
            })?;
        decode(response, mutation)
    }
    pub fn reconcile(&self, request: &OperationRequest) -> Result<OperationStatus, ErrorCode> {
        let (id, authority, policy, expected, kind, publication) = match request {
            OperationRequest::Publication(r) => {
                r.validate_structure()?;
                (
                    &r.operation_id,
                    &r.authority_id,
                    &r.policy_id,
                    &r.expected_revision,
                    OperationKind::Publication,
                    None,
                )
            }
            OperationRequest::Rollback(r) => {
                schema(r.schema_version)?;
                (
                    &r.operation_id,
                    &r.authority_id,
                    &r.policy_id,
                    &r.expected_revision,
                    OperationKind::Rollback,
                    Some(&r.publication_id),
                )
            }
        };
        self.identity(authority, policy)?;
        let status: OperationStatus = self.post_body("/api/policy/v1/reconcile", request, false)?;
        self.operation_identity(&status, id)?;
        if &status.expected_revision != expected
            || status.kind != kind
            || status.publication_id.as_ref() != publication
        {
            return Err(ErrorCode::InvalidResponse);
        }
        Ok(status)
    }
    pub fn current(&self) -> Result<PolicyDocument, ErrorCode> {
        let value: PolicyDocument = self.get("/api/policy/v1/current")?;
        self.identity(&value.authority_id, &value.policy_id)?;
        value.validate()?;
        if value.created_unix_ms > clock_ms()?.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err(ErrorCode::InvalidResponse);
        }
        Ok(value)
    }
    pub fn publish(&self, request: &PublicationRequest) -> Result<OperationStatus, ErrorCode> {
        self.identity(&request.authority_id, &request.policy_id)?;
        request.validate_structure()?;
        // The server decides freshness after idempotency lookup so an identical
        // committed request can still be reconciled after its review expires.
        let value: OperationStatus = self.post("/api/policy/v1/publications", request)?;
        self.operation_identity(&value, &request.operation_id)
            .map_err(|_| ErrorCode::OutcomeUnknown)?;
        if value.kind != OperationKind::Publication
            || value.expected_revision != request.expected_revision
        {
            return Err(ErrorCode::OutcomeUnknown);
        }
        Ok(value)
    }
    pub fn rollback(&self, request: &RollbackRequest) -> Result<OperationStatus, ErrorCode> {
        self.identity(&request.authority_id, &request.policy_id)?;
        schema(request.schema_version)?;
        let value: OperationStatus = self.post("/api/policy/v1/rollbacks", request)?;
        self.operation_identity(&value, &request.operation_id)
            .map_err(|_| ErrorCode::OutcomeUnknown)?;
        if value.kind != OperationKind::Rollback
            || value.expected_revision != request.expected_revision
            || value.publication_id.as_ref() != Some(&request.publication_id)
        {
            return Err(ErrorCode::OutcomeUnknown);
        }
        Ok(value)
    }
    fn operation_identity(&self, value: &OperationStatus, operation: &Id) -> Result<(), ErrorCode> {
        schema(value.schema_version)?;
        self.identity(&value.authority_id, &value.policy_id)?;
        if &value.operation_id != operation
            || value.created_unix_ms == 0
            || (value.outcome == OperationOutcome::Committed) != value.published_revision.is_some()
            || (value.outcome == OperationOutcome::Rejected) != value.failure_code.is_some()
            || (value.kind == OperationKind::Rollback) != value.publication_id.is_some()
            || (value.rollback_eligible
                && (value.outcome != OperationOutcome::Committed
                    || value.kind != OperationKind::Publication
                    || value.published_revision.as_ref() != Some(&value.current_revision)
                    || value.rollback_until_unix_ms.is_none()))
        {
            return Err(ErrorCode::InvalidResponse);
        }
        Ok(())
    }
    pub fn operation(&self, id: &Id) -> Result<OperationStatus, ErrorCode> {
        let value: OperationStatus =
            self.get(&format!("/api/policy/v1/operations/{}", id.as_str()))?;
        self.operation_identity(&value, id)?;
        Ok(value)
    }
    pub fn report(&self, request: &ClientReportRequest) -> Result<ReportReceipt, ErrorCode> {
        self.report_response(request, true)
    }
    /// Read-only lookup of the exact retained report. A receipt is historical
    /// and cannot substitute for current Runtime admission.
    pub fn reconcile_report(
        &self,
        request: &ClientReportRequest,
    ) -> Result<ReportReceipt, ErrorCode> {
        self.report_response(request, false)
    }
    fn report_response(
        &self,
        request: &ClientReportRequest,
        mutation: bool,
    ) -> Result<ReportReceipt, ErrorCode> {
        let invalid = if mutation {
            ErrorCode::OutcomeUnknown
        } else {
            ErrorCode::InvalidResponse
        };
        self.identity(&request.authority_id, &request.policy_id)?;
        request.validate_structure()?;
        let (client_id, _) = self.report_position()?;
        if request.report_id
            != report_id(&request.authority_id, &client_id, request.report_sequence)?
        {
            return Err(ErrorCode::InvalidRequest);
        }
        let path = if mutation {
            "/api/policy/v1/reports"
        } else {
            "/api/policy/v1/reports/reconcile"
        };
        let value: ReportReceipt = self.post_body(path, request, mutation)?;
        schema(value.schema_version).map_err(|_| invalid)?;
        self.identity(&value.authority_id, &value.policy_id)
            .map_err(|_| invalid)?;
        if value.report_id != request.report_id
            || value.client_id != client_id
            || value.report_sequence != request.report_sequence
            || value.received_unix_ms == 0
            || value.received_unix_ms > clock_ms()?.saturating_add(MAX_FUTURE_SKEW_MS)
        {
            return Err(invalid);
        }
        Ok(value)
    }
    pub fn status(&self) -> Result<FleetStatus, ErrorCode> {
        let value: FleetStatus = self.get("/api/policy/v1/status")?;
        self.identity(&value.authority_id, &value.policy_id)?;
        value.validate()?;
        if value.sampled_unix_ms.abs_diff(clock_ms()?) > MAX_FUTURE_SKEW_MS {
            return Err(ErrorCode::InvalidResponse);
        }
        Ok(value)
    }
}

#[cfg(test)]
#[path = "policy_team_client_tests.rs"]
mod tests;
