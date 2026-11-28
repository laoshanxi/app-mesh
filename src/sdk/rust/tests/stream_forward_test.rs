// stream_forward_test.rs: node forwarding on the streaming (SSE) path against a stub listener.
//
// A client with a forward target must forward its streams exactly like its other requests:
// the task runs on the target node, never silently on the local one.
//  - HTTP client: the stream request itself carries X-Target-Host.
//  - TCP/WSS clients: streams ride a direct HTTPS side channel. A forwarded stream dials
//    the agent REST listener (`agent_port`, which relays streams through node forwarding)
//    with X-Target-Host; a local stream keeps the engine listener and sends no target.
//  - A target the agent cannot reach fails the stream (502); it never falls back locally.

use appmesh::{
    AppMeshClient, AppMeshClientTCP, AppMeshClientWSS, AppMeshError, ClientBuilder, ClientBuilderTCP, ClientBuilderWSS,
    SseStream,
};
use mockito::{Matcher, Mock, Server, ServerOpts};
use std::sync::Arc;

const TASK_WIRE: &str = "event: final\ndata: {\"result\":\"node-b\"}\n\nevent: end\ndata: {\"reason\":\"final\"}\n\n";
const OUTPUT_WIRE: &str =
    "event: stdout\ndata: {\"output\":\"node-b\\n\",\"position\":0}\n\nevent: end\ndata: {\"position\":8,\"reason\":\"eof\"}\n\n";

/// A stub listener plus the mock keep-alive list: with `assert_on_drop` a mock handle
/// checks its expectations when it is dropped, so the handles live until the test ends.
struct Stub {
    // Declared first so the handles drop (and verify) before the listener goes away.
    mocks: Vec<Mock>,
    server: Server,
}

impl Stub {
    async fn new() -> Self {
        Self {
            server: Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await,
            mocks: Vec::new(),
        }
    }

    /// The stub's host and port (`server.url()` is `http://127.0.0.1:<port>`).
    fn address(&self) -> (String, u16) {
        let url = reqwest::Url::parse(&self.server.url()).expect("stub url");
        (url.host_str().unwrap().to_string(), url.port().expect("stub port"))
    }

    /// Expect one stream request; `target` is the required X-Target-Host (`None`: absent).
    async fn expect_stream(&mut self, method: &str, path: &str, target: Option<&str>, status: usize, body: &'static str) {
        let mock = self.server.mock(method, path).match_query(Matcher::Any).with_status(status).with_body(body);
        let mock = match target {
            Some(target) => mock.match_header("x-target-host", target),
            // Without a target the header is absent, not empty.
            None => mock.match_header("x-target-host", Matcher::Missing),
        };
        self.mocks.push(mock.create_async().await);
    }
}

async fn drain_task(mut stream: SseStream) -> String {
    while stream.next().await.expect("stream chunk").is_some() {}
    stream.end().expect("terminal marker").result.clone().expect("final result")
}

async fn drain_output(mut stream: SseStream) -> String {
    let mut out = String::new();
    while let Some(chunk) = stream.next().await.expect("stream chunk") {
        out.push_str(&chunk);
    }
    out
}

fn http_client(stub: &Stub) -> Arc<AppMeshClient> {
    ClientBuilder::new().url(stub.server.url()).danger_accept_invalid_certs(true).build().unwrap()
}

// A plain framed transport keeps the side channel on http:// so the stub can serve it; a
// streaming call never opens the framed connection itself.
fn framed_tcp(stub: &Stub) -> Arc<AppMeshClientTCP> {
    let (host, port) = stub.address();
    ClientBuilderTCP::new().host(host).port(port).plain_transport(true).agent_port(port).build().unwrap()
}

fn framed_wss(stub: &Stub) -> Arc<AppMeshClientWSS> {
    let (host, port) = stub.address();
    ClientBuilderWSS::new().host(host).port(port).plain_transport(true).agent_port(port).build().unwrap()
}

fn assert_bad_gateway(err: AppMeshError) {
    match err {
        AppMeshError::RequestFailed { status, .. } => assert_eq!(status, reqwest::StatusCode::BAD_GATEWAY),
        other => panic!("unexpected error: {:?}", other),
    }
}

#[tokio::test]
async fn http_client_forwards_task_stream() {
    let mut stub = Stub::new().await;
    stub.expect_stream("POST", "/appmesh/app/worker/task/stream", Some("appmesh_slave1"), 200, TASK_WIRE).await;
    let client = http_client(&stub);
    client.set_token("token");
    client.set_forward_to(Some("appmesh_slave1".to_string()));
    let stream = client.run_task_stream("worker", serde_json::json!("payload"), 30).await.unwrap();
    assert_eq!(drain_task(stream).await, "node-b");
}

#[tokio::test]
async fn http_client_local_stream_carries_no_target() {
    let mut stub = Stub::new().await;
    stub.expect_stream("GET", "/appmesh/app/worker/output/stream", None, 200, OUTPUT_WIRE).await;
    let client = http_client(&stub);
    client.set_token("token");
    let stream = client.follow_output("worker", 0, "", false, 30).await.unwrap();
    assert_eq!(drain_output(stream).await, "node-b\n");
}

#[tokio::test]
async fn http_client_bad_target_fails_the_stream() {
    let mut stub = Stub::new().await;
    stub.expect_stream("POST", "/appmesh/app/worker/task/stream", Some("appmesh_nosuch"), 502, "failed to forward request").await;
    let client = http_client(&stub);
    client.set_token("token");
    client.set_forward_to(Some("appmesh_nosuch".to_string()));
    assert_bad_gateway(client.run_task_stream("worker", serde_json::json!("payload"), 30).await.err().expect("must fail"));
}

#[tokio::test]
async fn tcp_client_forwards_streams_through_the_agent_listener() {
    let mut stub = Stub::new().await;
    stub.expect_stream("POST", "/appmesh/app/worker/task/stream", Some("appmesh_slave1"), 200, TASK_WIRE).await;
    stub.expect_stream("GET", "/appmesh/app/worker/output/stream", Some("appmesh_slave1"), 200, OUTPUT_WIRE).await;
    let client = framed_tcp(&stub);
    client.client().set_token("token");
    client.set_forward_to(Some("appmesh_slave1".to_string()));
    let stream = client.run_task_stream("worker", serde_json::json!("payload"), 30).await.unwrap();
    assert_eq!(drain_task(stream).await, "node-b");
    let stream = client.follow_output("worker", 0, "", false, 30).await.unwrap();
    assert_eq!(drain_output(stream).await, "node-b\n");
}

#[tokio::test]
async fn wss_client_forwards_streams_through_the_agent_listener() {
    let mut stub = Stub::new().await;
    stub.expect_stream("POST", "/appmesh/app/worker/task/stream", Some("appmesh_slave2"), 200, TASK_WIRE).await;
    stub.expect_stream("GET", "/appmesh/app/worker/output/stream", Some("appmesh_slave2"), 200, OUTPUT_WIRE).await;
    let client = framed_wss(&stub);
    client.client().set_token("token");
    client.set_forward_to(Some("appmesh_slave2".to_string()));
    let stream = client.run_task_stream("worker", serde_json::json!("payload"), 30).await.unwrap();
    assert_eq!(drain_task(stream).await, "node-b");
    let stream = client.follow_output("worker", 0, "", false, 30).await.unwrap();
    assert_eq!(drain_output(stream).await, "node-b\n");
}

#[tokio::test]
async fn framed_clients_local_stream_keeps_engine_listener_without_target() {
    let mut stub = Stub::new().await;
    let (host, port) = stub.address();
    // rest_port defaults to 6063: point the engine-listener hop at the stub too.
    stub.expect_stream("POST", "/appmesh/app/worker/task/stream", None, 200, TASK_WIRE).await;
    stub.expect_stream("GET", "/appmesh/app/worker/output/stream", None, 200, OUTPUT_WIRE).await;

    let tcp = ClientBuilderTCP::new().host(host.clone()).port(port).plain_transport(true).rest_port(port).build().unwrap();
    tcp.client().set_token("token");
    let stream = tcp.run_task_stream("worker", serde_json::json!("payload"), 30).await.unwrap();
    assert_eq!(drain_task(stream).await, "node-b");

    let wss = ClientBuilderWSS::new().host(host).port(port).plain_transport(true).rest_port(port).build().unwrap();
    wss.client().set_token("token");
    let stream = wss.follow_output("worker", 0, "", false, 30).await.unwrap();
    assert_eq!(drain_output(stream).await, "node-b\n");
}

#[tokio::test]
async fn tcp_client_bad_target_fails_the_stream() {
    let mut stub = Stub::new().await;
    stub.expect_stream("POST", "/appmesh/app/worker/task/stream", Some("appmesh_nosuch"), 502, "failed to forward request").await;
    let client = framed_tcp(&stub);
    client.client().set_token("token");
    client.set_forward_to(Some("appmesh_nosuch".to_string()));
    assert_bad_gateway(client.run_task_stream("worker", serde_json::json!("payload"), 30).await.err().expect("must fail"));
}
