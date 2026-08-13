//! Drive the packed component through `act run --mcp` with a real MCP client.
//!
//! This replaces the python fastmcp/pytest suite that used to live in this
//! directory: the tests observe exactly what an agent observes, over the same
//! client stack (`rmcp`) the host bridge itself is built on.
//!
//! Env: WASM — path to the packed component (default: the component's
//!      release build output);
//!      ACT  — the act invocation (default `act`; `npx @actcore/act`, the
//!             component justfile's default, also works — whitespace-split,
//!             like the shlex.split the python conftest did).

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use rmcp::{ServiceExt, model::CallToolRequestParams, transport::TokioChildProcess};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

/// `().serve(transport)` hands back the client-role service running over the
/// child process: role first, the unit client handler second.
type Client = rmcp::service::RunningService<rmcp::service::RoleClient, ()>;

fn wasm_path() -> PathBuf {
    PathBuf::from(std::env::var("WASM").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../target/wasm32-wasip2/release/component_crypto.wasm"
        )
        .into()
    }))
}

/// The ACT invocation, honouring the same override the component justfile
/// uses. Its default there is `npx @actcore/act` — two words — which cannot
/// be `argv[0]` for a non-shell spawn, so the value is whitespace-split into
/// program + leading args. Quoted paths with spaces are not a form this
/// fleet passes through `ACT`; a full shlex is deliberately not pulled in.
fn act_argv() -> Vec<String> {
    std::env::var("ACT")
        .unwrap_or_else(|_| "act".into())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Spawn `act run <wasm> --mcp` — with no grants.
///
/// crypto declares no capability ceiling (act.toml is `[std] name` only) and
/// every tool is pure computation, so there is nothing to grant: the python
/// conftest launched `act run` bare and so does this. For a component that
/// DID declare capabilities, grants would not be optional — the default
/// policy mode is `ask` and a headless run degrades it to deny.
fn act_command() -> tokio::process::Command {
    let argv = act_argv();
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..]);
    cmd.arg("run").arg(wasm_path()).arg("--mcp");
    cmd
}

fn spawn_transport() -> TokioChildProcess {
    TokioChildProcess::new(act_command()).expect("spawn act run --mcp")
}

/// Spawn with stderr captured: the audit trail (refusals, per-call rollup)
/// writes there unconditionally — RUST_LOG never silences it.
fn spawn_with_captured_stderr() -> (TokioChildProcess, Arc<AsyncMutex<String>>) {
    let (transport, stderr) = TokioChildProcess::builder(act_command())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn act run --mcp with piped stderr");

    let captured = Arc::new(AsyncMutex::new(String::new()));
    let sink = captured.clone();
    let mut lines = BufReader::new(stderr.expect("stderr was piped")).lines();
    tokio::spawn(async move {
        while let Ok(Some(line)) = lines.next_line().await {
            sink.lock().await.push_str(&line);
            sink.lock().await.push('\n');
        }
    });

    (transport, captured)
}

/// Poll the captured stderr until `needle` appears — the audit line is
/// flushed before the JSON-RPC reply, but reaching this buffer still crosses
/// a pipe and an async read.
async fn wait_for_stderr(
    captured: &Arc<AsyncMutex<String>>,
    needle: &str,
    timeout: Duration,
) -> bool {
    let start = std::time::Instant::now();
    loop {
        if captured.lock().await.contains(needle) {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn connect() -> Client {
    ().serve(spawn_transport())
        .await
        .expect("rmcp handshake with act run --mcp")
}

fn first_text_block(result: &rmcp::model::CallToolResult) -> &rmcp::model::TextContent {
    match result.content.first() {
        Some(rmcp::model::ContentBlock::Text(t)) => t,
        other => panic!("expected the first content block to be Text, got: {other:?}"),
    }
}

/// The kind and message of a failed call may arrive on either path: as a
/// JSON-RPC error response (`ErrorData.data` / `message`) or as an isError
/// result (`_meta` / text content). The python conftest's `expect_error`
/// fixture handled both; so does this. `call-tool` has no `result<>`
/// wrapper, so a guest reporting a failed call can only do it through
/// `tool-event::error` — which is the isError path here; the JSON-RPC path
/// stays handled for the non-guest failure modes.
async fn error_kind_of(client: &Client, params: CallToolRequestParams) -> (String, String) {
    match client.call_tool(params).await {
        Err(rmcp::ServiceError::McpError(e)) => {
            let kind = e
                .data
                .as_ref()
                .and_then(|d| d.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| "<no dev.actcore/error-kind in data>".into());
            (kind, e.message.to_string())
        }
        Ok(result) => {
            assert_eq!(result.is_error, Some(true), "call must fail: {result:?}");
            let kind = result
                .meta
                .as_ref()
                .and_then(|m| m.0.get("dev.actcore/error-kind"))
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| "<no dev.actcore/error-kind in _meta>".into());
            let message = first_text_block(&result).text.clone();
            (kind, message)
        }
        Err(other) => panic!("unexpected transport failure: {other:?}"),
    }
}

async fn call_tool(client: &Client, tool: &str, args: Value) -> rmcp::model::CallToolResult {
    // `new` takes a Cow<'static, str>: the &str parameter must be owned up.
    let params = CallToolRequestParams::new(tool.to_string())
        .with_arguments(args.as_object().expect("args are an object").clone());
    let result = client.call_tool(params).await.expect("call_tool");
    assert_ne!(result.is_error, Some(true), "{tool} failed: {result:?}");
    result
}

/// The manifest probe from the python test_info.py: the packed artifact
/// must declare its name and a version. Also the fast-fail the python
/// `wasm_path` fixture provided — an unpacked wasm (raw `cargo build`
/// output, no `act:component` section) declares no ceiling and the failures
/// point anywhere but at the missing metadata. The justfile's `test: build`
/// ordering exists so this test finds a packed artifact.
#[test]
fn manifest_reports_name_and_version() {
    let output = {
        let argv = act_argv();
        let mut cmd = std::process::Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.args(["inspect", "component-manifest"])
            .arg(wasm_path())
            .output()
            .expect("run act inspect component-manifest")
    };
    assert!(
        output.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest: Value = serde_json::from_slice(&output.stdout).expect("manifest is JSON");
    assert_eq!(
        manifest["std"]["name"], "crypto",
        "packed manifest must carry the component name"
    );
    assert!(
        manifest["std"]["version"].is_string(),
        "packed manifest must carry a version, got: {}",
        manifest["std"]["version"]
    );
}

/// python test_tools.py: `list_tools()` must return at least one tool.
#[tokio::test]
async fn component_exposes_its_tools() {
    let client = connect().await;
    let tools = client.list_all_tools().await.expect("list_all_tools");
    assert!(
        !tools.is_empty(),
        "component must expose at least one tool, got: {:?}",
        tools.iter().map(|t| t.name.to_string()).collect::<Vec<_>>()
    );
    client.cancel().await.ok();
}

/// One test per python parametrize case (test_hash.py CASES): pytest ran
/// them as six separate tests, so the rust suite keeps that granularity —
/// six fresh `act` processes, matching the function-scoped client fixture.
async fn assert_hash_of_hello(algorithm: Option<&str>, expected: &str) {
    let client = connect().await;

    let mut args = json!({"input": "hello"});
    if let Some(algorithm) = algorithm {
        args["algorithm"] = json!(algorithm);
    }
    let result = call_tool(&client, "hash", args).await;
    assert_eq!(
        first_text_block(&result).text,
        expected,
        "hash of \"hello\" with algorithm={algorithm:?}"
    );

    client.cancel().await.ok();
}

/// algorithm omitted → sha256, the tool's documented default.
#[tokio::test]
async fn hash_of_hello_defaults_to_sha256() {
    assert_hash_of_hello(
        None,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )
    .await
}

#[tokio::test]
async fn hash_of_hello_with_sha512() {
    assert_hash_of_hello(
        Some("sha512"),
        "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7\
         2323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
    )
    .await
}

#[tokio::test]
async fn hash_of_hello_with_sha3_256() {
    assert_hash_of_hello(
        Some("sha3-256"),
        "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392",
    )
    .await
}

#[tokio::test]
async fn hash_of_hello_with_md5() {
    assert_hash_of_hello(None.or(Some("md5")), "5d41402abc4b2a76b9719d911017c592").await
}

#[tokio::test]
async fn hash_of_hello_with_sha1() {
    assert_hash_of_hello(
        Some("sha1"),
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
    )
    .await
}

#[tokio::test]
async fn hash_of_hello_with_sha3_512() {
    assert_hash_of_hello(
        Some("sha3-512"),
        "75d527c368f2efe848ecf6b073a36767800805e9eef2b1857d5f984f036eb6df\
         891d75f72d9b154518c1cd58835286d1da9a38deba3de98b5a53e5ed78a84976",
    )
    .await
}

/// python test_hmac.py.
#[tokio::test]
async fn hmac_sha256_of_hello_with_secret_key() {
    let client = connect().await;

    let result = call_tool(
        &client,
        "hmac",
        json!({"message": "hello", "key": "secret"}),
    )
    .await;
    assert_eq!(
        first_text_block(&result).text,
        "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b"
    );

    client.cancel().await.ok();
}

/// python test_jwt_decode.py::test_decodes_a_valid_token.
#[tokio::test]
async fn jwt_decode_decodes_a_valid_token() {
    const TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\
                         .eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0\
                         .Gfx6VO9tcxwk6xqx9yYzSfebfeakZp5JYIgP_edcw_A";
    let client = connect().await;

    let result = call_tool(&client, "jwt_decode", json!({"token": TOKEN})).await;

    // Measured: crypto's jwt_decode does not populate structured_content —
    // the payload only ever arrives as a JSON-encoded text block. It is
    // still real JSON, so parse it and assert on fields rather than doing
    // substring matching on the raw string; that stays strictly stronger
    // than `contains` even without a populated structured_content.
    assert!(
        result.structured_content.is_none(),
        "jwt_decode must not populate structured_content, got: {:?}",
        result.structured_content
    );
    let decoded: Value =
        serde_json::from_str(&first_text_block(&result).text).expect("payload is JSON");
    assert_eq!(decoded["header"]["alg"], "HS256");
    assert_eq!(decoded["claims"]["sub"], "1234567890");
    assert_eq!(decoded["claims"]["name"], "John Doe");

    client.cancel().await.ok();
}

/// python test_jwt_decode.py::test_rejects_a_malformed_token. Task 1
/// measured this: it comes back as an isError RESULT carrying
/// dev.actcore/error-kind = "std:invalid-args", NOT as a raised exception,
/// because call-tool has no result<> wrapper for a guest to fail through.
#[tokio::test]
async fn jwt_decode_rejects_a_malformed_token() {
    let client = connect().await;

    let (kind, message) = error_kind_of(
        &client,
        CallToolRequestParams::new("jwt_decode").with_arguments(
            json!({"token": "not-a-jwt"})
                .as_object()
                .unwrap()
                .clone(),
        ),
    )
    .await;
    assert_eq!(
        kind, "std:invalid-args",
        "expected std:invalid-args for a malformed token, got {kind:?} ({message})"
    );

    client.cancel().await.ok();
}

/// Beyond python parity: the audit machinery. A tool call must leave its
/// rollup line on stderr, and the captured-stderr plumbing this harness
/// uses for refusals must actually see it.
#[tokio::test]
async fn hash_call_is_audited() {
    let (transport, captured) = spawn_with_captured_stderr();
    let client = ().serve(transport).await.expect("rmcp handshake");

    let result = call_tool(&client, "hash", json!({"input": "hello"})).await;
    assert_eq!(
        first_text_block(&result).text,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );

    assert!(
        wait_for_stderr(&captured, "req:", Duration::from_secs(5)).await,
        "expected a per-call rollup line in the audit trail:\n{}",
        captured.lock().await
    );

    client.cancel().await.ok();
}
