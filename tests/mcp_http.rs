//! `m1f mcp --http` end to end: the real binary on 127.0.0.1, driven with raw
//! HTTP the way the deploy-your-own connector's Worker reaches it through a
//! tunnel. Keychain-free: the bearer token comes from `M1F_MCP_TOKEN`, and
//! `M1F_KEYCHAIN_SERVICE` names a service that holds nothing, so the one
//! call made fails on its arguments before any read. The rules the server
//! enforces are cli-common's, tested there; this holds m1f to them.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

const TOKEN: &str = "5f0c1e2d3b4a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";
const TOOLS: [&str; 4] = [
    "m1_portfolio",
    "m1_activity",
    "m1_documents",
    "m1_realized_gains",
];

fn m1f() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_m1f"));
    c.env_remove("M1F_MCP_TOKEN")
        .env("M1F_KEYCHAIN_SERVICE", "piekstra.m1f-test-empty")
        .arg("--config")
        .arg(std::env::temp_dir().join(format!(
            "m1f-mcp-http-test-{}/config.json",
            std::process::id()
        )));
    c
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    port: u16,
}

impl Server {
    fn start() -> Self {
        let port = free_port();
        let mut child = m1f()
            .args(["mcp", "--http", "--port", &port.to_string()])
            .env("M1F_MCP_TOKEN", TOKEN)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("m1f starts");
        let deadline = Instant::now() + Duration::from_secs(20);
        while TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).is_err() {
            if let Some(status) = child.try_wait().unwrap() {
                let mut err = String::new();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut err)
                    .unwrap();
                panic!("m1f exited ({status}) before listening: {err}");
            }
            assert!(Instant::now() < deadline, "m1f did not listen on {port}");
            std::thread::sleep(Duration::from_millis(50));
        }
        Self { child, port }
    }

    /// One POST /mcp: the status and the JSON body.
    fn post(&self, auth: Option<&str>, body: Value) -> (u16, Value) {
        let mut stream = TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], self.port))).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let body = body.to_string();
        let mut req = format!(
            "POST /mcp HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
             Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n\
             MCP-Protocol-Version: 2025-11-25\r\nContent-Length: {}\r\n",
            body.len()
        );
        if let Some(token) = auth {
            req.push_str(&format!("Authorization: Bearer {token}\r\n"));
        }
        req.push_str("\r\n");
        req.push_str(&body);
        stream.write_all(req.as_bytes()).unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").expect("a response head");
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        (
            status,
            serde_json::from_str(body.trim()).unwrap_or(Value::Null),
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn the_worker_gets_the_four_read_only_tools_with_the_token_only() {
    let s = Server::start();
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

    let (status, _) = s.post(None, list.clone());
    assert_eq!(status, 401, "no token");
    let (status, _) = s.post(Some(&TOKEN.replace('5', "6")), list.clone());
    assert_eq!(status, 401, "a wrong token");

    let (status, got) = s.post(Some(TOKEN), list);
    assert_eq!(status, 200, "{got}");
    let names: Vec<&str> = got["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, TOOLS);

    // A call goes through to the tool, which refuses a bad date before it
    // reads the (empty) keychain.
    let (_, call) = s.post(
        Some(TOKEN),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "m1_activity", "arguments": {"since": "yesterday"}}}),
    );
    assert_eq!(call["result"]["isError"], true, "{call}");
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("usage:"), "{text}");
}

#[test]
fn it_will_not_start_without_a_port_or_a_usable_token() {
    let out = m1f().args(["mcp", "--http"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2), "no --port");

    let out = m1f()
        .args(["mcp", "--http", "--port", &free_port().to_string()])
        .env("M1F_MCP_TOKEN", "too-short")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("M1F_MCP_TOKEN"));
}
