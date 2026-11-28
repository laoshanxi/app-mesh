// sync_run_test.rs: paging of truncated `run_app_sync` output against a stub server.

use appmesh::{
    AppMeshClient, AppMeshError, ClientBuilder, SYNC_RUN_OUTPUT_PAGE_BYTES, SYNC_RUN_TRUNCATED_RETENTION_SECONDS,
};
use mockito::{Matcher, Mock, Server, ServerOpts};
use std::sync::Arc;

fn create_test_client(server: &Server) -> Arc<AppMeshClient> {
    ClientBuilder::new().url(server.url()).danger_accept_invalid_certs(true).build().unwrap()
}

fn full_page(fill: u8) -> Vec<u8> {
    vec![fill; SYNC_RUN_OUTPUT_PAGE_BYTES]
}

#[tokio::test]
async fn first_page_over_ceiling_raises_without_paging() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-7")
            .with_body(full_page(b'a'))
            .expect(1)
            .create_async()
            .await,
    );
    server
        .mock("GET", "/appmesh/app/run-7/output")
        .match_query(Matcher::Any)
        .with_status(200)
        .expect(0)
        .create_async()
        .await;
    server.mock("DELETE", "/appmesh/app/run-7").with_status(200).expect(0).create_async().await;

    let client = create_test_client(&server);
    let ceiling = SYNC_RUN_OUTPUT_PAGE_BYTES as u64 - 10;
    let err = client.run_sync_with_max_output("cat big", 60, 120, Some(ceiling)).await.unwrap_err();
    assert!(
        matches!(err, AppMeshError::OutputLimitExceeded { max_output_bytes, ref app_name, .. } if max_output_bytes == ceiling && app_name == "run-7")
    );
    drop(mocks);
}

#[tokio::test]
async fn short_final_page_crossing_ceiling_raises_and_keeps_the_run() {
    // 1.4 pages: the first page is under the ceiling, the short final page crosses it.
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(truncated_sync_run(&mut server, "run-8", full_page(b'a')).await);
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-8/output")
            .match_query(Matcher::UrlEncoded("stdout_position".into(), SYNC_RUN_OUTPUT_PAGE_BYTES.to_string()))
            .with_status(200)
            .with_body(vec![b'b'; 4 * SYNC_RUN_OUTPUT_PAGE_BYTES / 10])
            .expect(1)
            .create_async()
            .await,
    );
    server.mock("DELETE", "/appmesh/app/run-8").with_status(200).expect(0).create_async().await;

    let client = create_test_client(&server);
    let ceiling = SYNC_RUN_OUTPUT_PAGE_BYTES as u64 + 10;
    let err = client.run_sync_with_max_output("cat big", 60, 120, Some(ceiling)).await.unwrap_err();
    assert!(
        matches!(err, AppMeshError::OutputLimitExceeded { max_output_bytes, ref app_name, .. } if max_output_bytes == ceiling && app_name == "run-8")
    );
    drop(mocks);
}

#[tokio::test]
async fn empty_final_page_is_still_under_ceiling() {
    // One full page and an empty follow-up: exactly the ceiling, so the run is returned and deleted.
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(truncated_sync_run(&mut server, "run-9", full_page(b'a')).await);
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-9/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("")
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(server.mock("DELETE", "/appmesh/app/run-9").with_status(200).expect(1).create_async().await);

    let client = create_test_client(&server);
    let ceiling = SYNC_RUN_OUTPUT_PAGE_BYTES as u64;
    let (_, output) = client.run_sync_with_max_output("cat big", 60, 120, Some(ceiling)).await.unwrap();
    assert_eq!(output.len(), ceiling as usize);
    drop(mocks);
}

#[tokio::test]
async fn exactly_at_ceiling_with_short_final_page_deletes_the_run() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(truncated_sync_run(&mut server, "run-10", full_page(b'a')).await);
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-10/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("tail")
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(server.mock("DELETE", "/appmesh/app/run-10").with_status(200).expect(1).create_async().await);

    let client = create_test_client(&server);
    let ceiling = SYNC_RUN_OUTPUT_PAGE_BYTES as u64 + 4;
    let (_, output) = client.run_sync_with_max_output("cat big", 60, 120, Some(ceiling)).await.unwrap();
    assert_eq!(output.len(), ceiling as usize);
    drop(mocks);
}

/// A truncated sync-run reply (full first page, truncated headers, named run).
async fn truncated_sync_run(server: &mut Server, run_name: &str, first_page: Vec<u8>) -> Mock {
    server
        .mock("POST", "/appmesh/app/syncrun")
        .match_query(Matcher::Any)
        .with_status(200)
        .with_header("X-Exit-Code", "0")
        .with_header("X-Output-Truncated", "1")
        .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
        .with_header("X-App-Name", run_name)
        .with_body(first_page)
        .expect(1)
        .create_async()
        .await
}
#[tokio::test]
async fn untruncated_run_keeps_legacy_return_value() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "3")
            .with_body("execution successful")
            .expect(1)
            .create_async()
            .await,
    );

    let client = create_test_client(&server);
    let (exit_code, output) = client.run_sync("echo hello", 60, 120).await.unwrap();
    assert_eq!(exit_code, Some(3));
    assert_eq!(output, "execution successful");
    // No truncation headers: nothing is paged and nothing is deleted.
}

#[tokio::test]
async fn truncated_run_collects_pages_and_advances_byte_cursor() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Exit-Code", "0")
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-1")
            .with_body(full_page(b'a'))
            .expect(1)
            .create_async()
            .await,
    );
    // Second page is full, third is short: the run ends there.
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-1/output")
            .match_query(Matcher::UrlEncoded("stdout_position".into(), SYNC_RUN_OUTPUT_PAGE_BYTES.to_string()))
            .with_status(200)
            .with_body(full_page(b'b'))
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-1/output")
            .match_query(Matcher::UrlEncoded("stdout_position".into(), (2 * SYNC_RUN_OUTPUT_PAGE_BYTES).to_string()))
            .with_status(200)
            .with_body("tail")
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server
            .mock("DELETE", "/appmesh/app/run-1")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body("true")
            .expect(1)
            .create_async()
            .await,
    );

    let client = create_test_client(&server);
    let (exit_code, output) = client.run_sync("cat big", 60, 120).await.unwrap();
    assert_eq!(exit_code, Some(0));
    let mut expected = full_page(b'a');
    expected.extend(full_page(b'b'));
    expected.extend_from_slice(b"tail");
    assert_eq!(output.as_bytes(), expected.as_slice());
}

#[tokio::test]
async fn exactly_one_page_reads_one_empty_page() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-2")
            .with_body(full_page(b'x'))
            .expect(1)
            .create_async()
            .await,
    );
    // Exactly one page: the follow-up read returns nothing, which also means "complete".
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-2/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("")
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server.mock("DELETE", "/appmesh/app/run-2").with_status(404).with_body("false").expect(1).create_async().await,
    );

    let client = create_test_client(&server);
    let (exit_code, output) = client.run_sync("cat big", 60, 120).await.unwrap();
    assert_eq!(exit_code, None);
    assert_eq!(output.as_bytes(), full_page(b'x').as_slice());
}

#[tokio::test]
async fn multibyte_character_split_across_pages_is_kept() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    // The 3-byte character lands on the page boundary: 1 byte on page 1, 2 bytes on page 2.
    let mut first = full_page(b'a');
    first[SYNC_RUN_OUTPUT_PAGE_BYTES - 1] = "世".as_bytes()[0];
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-3")
            .with_body(first)
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-3/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(&"世".as_bytes()[1..])
            .expect(1)
            .create_async()
            .await,
    );

    let client = create_test_client(&server);
    let (_, output) = client.run_sync("cat big", 60, 120).await.unwrap();
    let mut expected = String::from_utf8(full_page(b'a')).unwrap();
    expected.pop();
    expected.push('世');
    assert_eq!(output, expected);
}

#[tokio::test]
async fn max_output_exceeded_errors_and_keeps_the_run() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-4")
            .with_body(full_page(b'a'))
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-4/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body(full_page(b'b'))
            .expect(1)
            .create_async()
            .await,
    );
    // The run must stay readable: no DELETE, no further paging.

    let client = create_test_client(&server);
    let ceiling = SYNC_RUN_OUTPUT_PAGE_BYTES as u64 + 1024;
    let err = client.run_sync_with_max_output("cat big", 60, 120, Some(ceiling)).await.unwrap_err();
    match &err {
        AppMeshError::OutputLimitExceeded { max_output_bytes, app_name, retention_seconds } => {
            assert_eq!(*max_output_bytes, ceiling);
            assert_eq!(app_name, "run-4");
            assert_eq!(*retention_seconds, SYNC_RUN_TRUNCATED_RETENTION_SECONDS);
        }
        other => panic!("unexpected error: {:?}", other),
    }
    assert!(err.to_string().contains(&format!("max_output_bytes={}", ceiling)), "{}", err);
    assert!(
        err.to_string().contains(&format!("application 'run-4' for {} seconds", SYNC_RUN_TRUNCATED_RETENTION_SECONDS)),
        "{}",
        err
    );
}

#[tokio::test]
async fn max_output_not_exceeded_still_deletes_the_run() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-5")
            .with_body(full_page(b'a'))
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-5/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("tail")
            .expect(1)
            .create_async()
            .await,
    );

    let client = create_test_client(&server);
    let (_, output) =
        client.run_sync_with_max_output("cat big", 60, 120, Some(SYNC_RUN_OUTPUT_PAGE_BYTES as u64 + 1024)).await.unwrap();
    assert_eq!(output.len(), SYNC_RUN_OUTPUT_PAGE_BYTES + 4);
}

#[tokio::test]
async fn failed_run_delete_is_tolerated() {
    let mut server = Server::new_with_opts_async(ServerOpts { assert_on_drop: true, ..Default::default() }).await;
    // assert_on_drop checks each expect(n) when the mocks are dropped.
    let mut mocks: Vec<Mock> = Vec::new();
    mocks.push(
        server
            .mock("POST", "/appmesh/app/syncrun")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_header("X-Output-Truncated", "1")
            .with_header("X-Output-Position", &SYNC_RUN_OUTPUT_PAGE_BYTES.to_string())
            .with_header("X-App-Name", "run-6")
            .with_body(full_page(b'a'))
            .expect(1)
            .create_async()
            .await,
    );
    mocks.push(
        server
            .mock("GET", "/appmesh/app/run-6/output")
            .match_query(Matcher::Any)
            .with_status(200)
            .with_body("tail")
            .expect(1)
            .create_async()
            .await,
    );

    let client = create_test_client(&server);
    let (_, output) = client.run_sync("cat big", 60, 120).await.unwrap();
    assert_eq!(output.len(), SYNC_RUN_OUTPUT_PAGE_BYTES + 4);
}
