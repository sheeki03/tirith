use super::*;
use crate::store::unix_ms;
use std::os::unix::fs::PermissionsExt;
use tower::ServiceExt;
struct Fixture {
    _root: tempfile::TempDir,
    store: Arc<Store>,
    token: String,
}
impl Fixture {
    fn new() -> Self {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "native server tests require ordinary owner"
        );
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store = Arc::new(Store::initialize(&base.join("authority"), "paranoia: 2\n").unwrap());
        let identity = store.identity().unwrap();
        let output = base.join("publisher.token");
        store
            .issue_credential(
                &identity.authority_id,
                Role::Publisher,
                &Id::new(),
                None,
                unix_ms().unwrap() + 60_000,
                &output,
            )
            .unwrap();
        let token = std::fs::read_to_string(output)
            .unwrap()
            .trim_end_matches('\n')
            .into();
        Self {
            _root: root,
            store,
            token,
        }
    }
    fn request(&self, method: Method, path: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {}", self.token))
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)
            .unwrap()
    }
}
#[tokio::test]
async fn auth_origin_query_and_canonical_route_checks_are_closed() {
    let fixture = Fixture::new();
    let app = router(App::new(fixture.store.clone()));
    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/policy/v1/current")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    for path in [
        "/api/policy/v1/current?token=anything",
        "/api/policy/v1/operations/00000000-0000-0000-0000-000000000000",
        "/api/policy/v1/operations/../current",
    ] {
        let reply = app
            .clone()
            .oneshot(fixture.request(Method::GET, path, Body::empty()))
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::BAD_REQUEST);
    }
    let mut origin = fixture.request(Method::GET, "/api/policy/v1/current", Body::empty());
    origin.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://browser.invalid"),
    );
    assert_eq!(
        app.clone().oneshot(origin).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let mut duplicate = fixture.request(Method::GET, "/api/policy/v1/current", Body::empty());
    duplicate.headers_mut().append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer attacker"),
    );
    assert_eq!(
        app.clone().oneshot(duplicate).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let good = app
        .oneshot(fixture.request(Method::GET, "/api/policy/v1/current", Body::empty()))
        .await
        .unwrap();
    assert_eq!(good.status(), StatusCode::OK);
    assert_eq!(good.headers()[header::CACHE_CONTROL], "no-store");
}
#[tokio::test]
async fn legacy_fetch_is_actual_yaml_with_authority_ids_and_no_report() {
    let fixture = Fixture::new();
    let identity = fixture.store.identity().unwrap();
    let app = router(App::new(fixture.store.clone()));
    let reply = app
        .oneshot(fixture.request(Method::GET, "/api/policy/fetch", Body::empty()))
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(
        reply.headers()["x-tirith-authority-id"],
        identity.authority_id.as_str()
    );
    assert_eq!(
        &to_bytes(reply.into_body(), MAX_POLICY_BYTES).await.unwrap()[..],
        b"paranoia: 2\n"
    );
    assert!(fixture
        .store
        .status(&fixture.token)
        .unwrap()
        .clients
        .is_empty());
}
#[tokio::test]
async fn rejected_body_size_and_unknown_fields_do_not_publish() {
    let fixture = Fixture::new();
    let before = fixture.store.identity().unwrap().current_revision;
    let app = router(App::new(fixture.store.clone()));
    let mut request = fixture.request(
        Method::POST,
        "/api/policy/v1/publications",
        Body::from("{}"),
    );
    request.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&(MAX_REQUEST_BYTES + 1).to_string()).unwrap(),
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
    let request = fixture.request(
        Method::POST,
        "/api/policy/v1/publications",
        Body::from("{\"extra\":\"never echo this\"}"),
    );
    let reply = app.oneshot(request).await.unwrap();
    assert_eq!(reply.status(), StatusCode::BAD_REQUEST);
    let bytes = to_bytes(reply.into_body(), 1024).await.unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("never echo"));
    assert_eq!(fixture.store.identity().unwrap().current_revision, before);
}
#[tokio::test]
async fn native_slow_header_and_body_close_at_original_connection_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, receive) = tokio::sync::oneshot::channel();
    let store = fixture.store.clone();
    let server = tokio::spawn(serve_listener(store, listener, async {
        let _ = receive.await;
        Ok(())
    }));
    let before = fixture.store.identity().unwrap().current_revision;
    let started = std::time::Instant::now();
    let mut header_stream = tokio::net::TcpStream::connect(address).await.unwrap();
    header_stream
        .write_all(b"GET /api/policy/v1/current HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    let mut body_stream = tokio::net::TcpStream::connect(address).await.unwrap();
    body_stream.write_all(format!("POST /api/policy/v1/publications HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{",fixture.token).as_bytes()).await.unwrap();
    let read = async {
        let mut first = Vec::new();
        let mut second = Vec::new();
        let a = header_stream.read_to_end(&mut first);
        let b = body_stream.read_to_end(&mut second);
        let (a, b) = tokio::join!(a, b);
        assert!(a.is_ok());
        assert!(b.is_ok());
    };
    tokio::time::timeout(Duration::from_secs(12), read)
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(9));
    assert!(started.elapsed() < Duration::from_secs(12));
    // EOF is only transport closure; never mislabel it as an HTTP408 response.
    assert_eq!(fixture.store.identity().unwrap().current_revision, before);
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
}
