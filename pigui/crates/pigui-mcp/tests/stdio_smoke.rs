use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn lists_tools_and_reports_daemon_errors_cleanly() {
    let home = tempfile::tempdir().unwrap();
    let socket = home.path().join("missing.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_pigui-mcp"))
        .env("PIGUI_HOME", home.path())
        .env("PIGUI_SOCKET", &socket)
        .env("RUST_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pigui-mcp");

    {
        let stdin = child.stdin.as_mut().expect("stdin");
        writeln!(
            stdin,
            "{}",
            json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"initialize",
                "params":{
                    "protocolVersion":"2025-11-25",
                    "capabilities":{},
                    "clientInfo":{"name":"pigui-mcp-test","version":"1"}
                }
            })
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"status","arguments":{}}})
        )
        .unwrap();
        writeln!(
            stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"overview","arguments":{"limit":3}}})
        )
        .unwrap();
    }
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let responses = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("stdout must contain only JSON"))
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 4);

    let initialize = responses
        .iter()
        .find(|response| response["id"] == 1)
        .unwrap();
    assert_eq!(initialize["result"]["protocolVersion"], "2025-11-25");

    let tools = responses
        .iter()
        .find(|response| response["id"] == 2)
        .unwrap();
    let tools = tools["result"]["tools"].as_array().unwrap();
    for name in ["status", "overview", "findings", "destination_detail"] {
        assert!(tools.iter().any(|tool| tool["name"] == name), "{name}");
    }
    for tool in tools {
        let annotations = &tool["annotations"];
        assert_eq!(annotations["readOnlyHint"], true);
        assert_eq!(annotations["destructiveHint"], false);
        assert_eq!(annotations["openWorldHint"], false);
    }

    let status = responses
        .iter()
        .find(|response| response["id"] == 3)
        .unwrap();
    assert_eq!(status["result"]["isError"], true);
    let text = status["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("pigui-daemon"), "{text}");
    assert!(text.contains("PIGUI_SOCKET"), "{text}");

    let overview = responses
        .iter()
        .find(|response| response["id"] == 4)
        .unwrap();
    assert_eq!(overview["result"]["isError"], true);
    let text = overview["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("analysis.overview"), "{text}");
}
