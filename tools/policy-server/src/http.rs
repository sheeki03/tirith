//! Loopback transport for an operator-provided HTTPS reverse proxy. No browser
//! authority, URL credentials, forwarding-header authentication, or request logs.
use crate::store::Store;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    response::Response,
    Router,
};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tirith_core::policy_team::*;
use tokio::{
    net::TcpListener,
    sync::Semaphore,
    task::JoinSet,
    time::{timeout_at, Instant},
};

const REQUEST_TIME: Duration = Duration::from_secs(10);
const REPORT_BYTES: usize = 8192;
#[derive(Clone, Copy)]
struct ConnectionDeadline(Instant);
#[derive(Clone)]
pub struct App {
    store: Arc<Store>,
    workers: Arc<Semaphore>,
}
impl App {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            workers: Arc::new(Semaphore::new(32)),
        }
    }
}
#[derive(Clone, Copy)]
enum Route {
    Health,
    Capabilities,
    Current,
    Fetch,
    Publication,
    Rollback,
    Report,
    ReconcileReport,
    Status,
    Operation,
    Reconcile,
}
impl Route {
    fn read_roles(self) -> &'static [Role] {
        match self {
            Self::Publication | Self::Rollback | Self::Reconcile => &[Role::Publisher],
            Self::Report | Self::ReconcileReport => &[Role::Client],
            Self::Status | Self::Operation => &[Role::Publisher, Role::Observer],
            _ => &[Role::Publisher, Role::Observer, Role::Client],
        }
    }
    fn has_json_body(self) -> bool {
        matches!(
            self,
            Self::Publication
                | Self::Rollback
                | Self::Report
                | Self::Reconcile
                | Self::ReconcileReport
        )
    }
}
fn route(method: &Method, path: &str) -> Result<(Route, Option<Id>), ErrorCode> {
    let selected = match (method, path) {
        (&Method::GET, "/healthz") => Route::Health,
        (&Method::GET, "/api/policy/v1/capabilities") => Route::Capabilities,
        (&Method::GET, "/api/policy/v1/current") => Route::Current,
        (&Method::GET, "/api/policy/fetch") => Route::Fetch,
        (&Method::POST, "/api/policy/v1/publications") => Route::Publication,
        (&Method::POST, "/api/policy/v1/rollbacks") => Route::Rollback,
        (&Method::POST, "/api/policy/v1/reconcile") => Route::Reconcile,
        (&Method::POST, "/api/policy/v1/reports") => Route::Report,
        (&Method::POST, "/api/policy/v1/reports/reconcile") => Route::ReconcileReport,
        (&Method::GET, "/api/policy/v1/status") => Route::Status,
        (&Method::GET, path) if path.starts_with("/api/policy/v1/operations/") => {
            let id = Id::parse(&path["/api/policy/v1/operations/".len()..])?;
            return Ok((Route::Operation, Some(id)));
        }
        _ => return Err(ErrorCode::InvalidRequest),
    };
    Ok((selected, None))
}
fn bearer(headers: &HeaderMap) -> Result<String, ErrorCode> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(ErrorCode::Unauthorized)?;
    if values.next().is_some() {
        return Err(ErrorCode::Unauthorized);
    }
    let text = value.to_str().map_err(|_| ErrorCode::Unauthorized)?;
    let token = text
        .strip_prefix("Bearer ")
        .ok_or(ErrorCode::Unauthorized)?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(token.into())
}
fn response(status: StatusCode, bytes: Vec<u8>, content: &'static str) -> Response {
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content));
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
fn error(code: ErrorCode) -> Response {
    let status = match code {
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::Forbidden => StatusCode::FORBIDDEN,
        ErrorCode::PolicyUninitialized | ErrorCode::OperationNotFound => StatusCode::NOT_FOUND,
        ErrorCode::AuthorityChanged
        | ErrorCode::RevisionConflict
        | ErrorCode::OperationConflict
        | ErrorCode::ReportOutOfOrder => StatusCode::CONFLICT,
        ErrorCode::StorageUnavailable | ErrorCode::CapacityExceeded => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        ErrorCode::OutcomeUnknown | ErrorCode::TransportUnavailable => StatusCode::GATEWAY_TIMEOUT,
        _ => StatusCode::BAD_REQUEST,
    };
    // Closed enum and fixed schema only; no parser, SQL, request or token details.
    let body = serde_json::to_vec(&ErrorResponse {
        schema_version: SCHEMA_VERSION,
        error: code,
    })
    .unwrap_or_else(|_| b"{\"schema_version\":1,\"error\":\"storage_unavailable\"}".to_vec());
    response(status, body, "application/json")
}
fn json_response<T: serde::Serialize>(value: &T) -> Result<Response, ErrorCode> {
    let bytes = serde_json::to_vec(value).map_err(|_| ErrorCode::StorageUnavailable)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ErrorCode::StorageUnavailable);
    }
    Ok(response(StatusCode::OK, bytes, "application/json"))
}
fn decoded<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ErrorCode> {
    serde_json::from_slice(bytes).map_err(|_| ErrorCode::InvalidRequest)
}
async fn database<T: Send + 'static>(
    app: &App,
    deadline: Instant,
    run: impl FnOnce(&Store) -> Result<T, ErrorCode> + Send + 'static,
) -> Result<T, ErrorCode> {
    // Keep this permit inside the blocking worker if the HTTP future times out.
    // Timed-out COMMIT may still have completed: mutation reply is outcome_unknown.
    let permit = app
        .workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    let store = app.store.with_deadline(deadline.into_std());
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        run(&store)
    })
    .await
    .map_err(|_| ErrorCode::StorageUnavailable)?
}
async fn request_inner(
    app: App,
    request: Request<Body>,
    deadline: Instant,
) -> Result<Response, ErrorCode> {
    if request.uri().query().is_some()
        || request.uri().scheme().is_some()
        || request.headers().contains_key(header::ORIGIN)
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let (route, operation) = route(request.method(), request.uri().path())?;
    if matches!(route, Route::Health) {
        return Ok(response(
            StatusCode::OK,
            b"{\"schema_version\":1,\"status\":\"available\"}".to_vec(),
            "application/json",
        ));
    }
    let token = bearer(request.headers())?;
    let cap = if matches!(route, Route::Report | Route::ReconcileReport) {
        REPORT_BYTES
    } else {
        MAX_REQUEST_BYTES
    };
    let lengths: Vec<_> = request
        .headers()
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .collect();
    if lengths.len() > 1 {
        return Err(ErrorCode::InvalidRequest);
    }
    if let Some(length) = lengths.first() {
        let length = length
            .to_str()
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .ok_or(ErrorCode::InvalidRequest)?;
        if length > cap {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    if route.has_json_body() {
        let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
        if types.next().and_then(|v| v.to_str().ok()) != Some("application/json")
            || types.next().is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
    }
    let check = token.clone();
    database(&app, deadline, move |store| {
        store.authorize(&check, route.read_roles())
    })
    .await?;
    let bytes = to_bytes(
        request.into_body(),
        if route.has_json_body() { cap } else { 0 },
    )
    .await
    .map_err(|_| ErrorCode::InvalidRequest)?;
    database(&app, deadline, move |store| match route {
        Route::Capabilities => json_response(&store.capabilities(&token)?),
        Route::Current => json_response(&store.current(&token)?),
        Route::Fetch => {
            let document = store.current(&token)?;
            if document.yaml.len() > MAX_POLICY_BYTES {
                return Err(ErrorCode::StorageUnavailable);
            }
            let mut out = response(
                StatusCode::OK,
                document.yaml.into_bytes(),
                "application/yaml",
            );
            for (name, id) in [
                ("x-tirith-authority-id", document.authority_id),
                ("x-tirith-policy-id", document.policy_id),
                ("x-tirith-policy-revision", document.revision),
            ] {
                out.headers_mut().insert(
                    name,
                    HeaderValue::from_str(id.as_str())
                        .map_err(|_| ErrorCode::StorageUnavailable)?,
                );
            }
            Ok(out)
        }
        Route::Publication => json_response(&store.publish(&token, decoded(&bytes)?)?),
        Route::Rollback => json_response(&store.rollback(&token, decoded(&bytes)?)?),
        Route::Reconcile => json_response(&store.reconcile(&token, decoded(&bytes)?)?),
        Route::Report => json_response(&store.report(&token, decoded(&bytes)?)?),
        Route::ReconcileReport => json_response(&store.reconcile_report(&token, decoded(&bytes)?)?),
        Route::Status => json_response(&store.status(&token)?),
        Route::Operation => json_response(
            &store.operation_status(&token, &operation.ok_or(ErrorCode::InvalidRequest)?)?,
        ),
        Route::Health => Err(ErrorCode::InvalidRequest),
    })
    .await
}
async fn request(State(app): State<App>, request: Request<Body>) -> Response {
    let mutating = request.method() == Method::POST;
    let deadline = request
        .extensions()
        .get::<ConnectionDeadline>()
        .map_or(Instant::now() + REQUEST_TIME, |value| value.0);
    match timeout_at(deadline, request_inner(app, request, deadline)).await {
        Ok(Ok(response)) => response,
        Ok(Err(code)) => error(code),
        Err(_) => error(if mutating {
            ErrorCode::OutcomeUnknown
        } else {
            ErrorCode::TransportUnavailable
        }),
    }
}
pub fn router(app: App) -> Router {
    Router::new().fallback(request).with_state(app)
}

/// One request per connection avoids idle keepalive retaining a slot. Header
/// acquisition and the whole connection have bounded native async deadlines.
pub async fn serve(store: Arc<Store>, address: SocketAddr) -> Result<(), ErrorCode> {
    if !address.ip().is_loopback() {
        return Err(ErrorCode::InvalidRequest);
    }
    let listener = TcpListener::bind(address)
        .await
        .map_err(|_| ErrorCode::StorageUnavailable)?;
    serve_listener(store, listener, tokio::signal::ctrl_c()).await
}
pub async fn serve_listener<F>(
    store: Arc<Store>,
    listener: TcpListener,
    shutdown: F,
) -> Result<(), ErrorCode>
where
    F: std::future::Future<Output = std::io::Result<()>> + Send,
{
    if !listener
        .local_addr()
        .map_err(|_| ErrorCode::StorageUnavailable)?
        .ip()
        .is_loopback()
    {
        return Err(ErrorCode::InvalidRequest);
    }
    let app = router(App::new(store));
    let slots = Arc::new(Semaphore::new(32));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _=&mut shutdown=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=> {
                let (stream,_)=accepted.map_err(|_|ErrorCode::StorageUnavailable)?;
                let Ok(permit)=slots.clone().try_acquire_owned() else {drop(stream);continue;};
                let deadline=Instant::now()+REQUEST_TIME;
                let service=TowerToHyperService::new(app.clone().layer(axum::Extension(ConnectionDeadline(deadline))));
                tasks.spawn(async move {
                    let _permit=permit;
                    let mut builder=http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(REQUEST_TIME).keep_alive(false).max_headers(32).max_buf_size(32*1024);
                    let connection=builder.serve_connection(TokioIo::new(stream),service);
                    // The handler's deadline starts after headers. This outer
                    // bound includes header/body acquisition and response writes.
                    let _=timeout_at(deadline,connection).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
