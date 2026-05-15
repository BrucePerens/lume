use reqwest::Client;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

// [@ANCHOR: integration_api_daemon_test]
#[tokio::test]
async fn test_api_daemon_extensively_via_subprocess() {
    // 1. Spawn the actual compiled daemon as a child process using the dev flag
    let mut child = Command::new(env!("CARGO_BIN_EXE_lume"))
        .arg("--dev-mode")
        .arg("--port")
        .arg("0") // Request ephemeral port
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Lume daemon child process");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut bound_url = String::new();

    // 2. Wait for the daemon to announce its port
    // We expect a line like: "🚀 DEV Lume Server spinning up at http://127.0.0.1:XXXXX"
    for _ in 0..50 {
        // Timeout loop
        line.clear();
        if reader.read_line(&mut line).unwrap() > 0 {
            if line.contains("spinning up at http://") {
                let parts: Vec<&str> = line.split("http://").collect();
                if parts.len() == 2 {
                    bound_url = format!("http://{}", parts[1].trim());
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        !bound_url.is_empty(),
        "Daemon failed to start or report its port in time"
    );

    let client = Client::new();

    // Test A: Store an email securely with correct authentication
    let store_payload = serde_json::json!({
        "message_id": "api_msg_100",
        "subject": "Extensive Subprocess Test",
        "sender": "integration@test.com",
        "raw_content": [84, 104, 105, 115, 32, 105, 115, 32, 116, 104, 101, 32, 112, 97, 121, 108, 111, 97, 100] // "This is the payload"
    });

    let res = client
        .post(format!("{}/mail", bound_url))
        .basic_auth("api_test_user", Some("secure_password"))
        .json(&store_payload)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 201, "Failed to store email via subprocess");

    // Test B: Retrieve the stored email successfully
    let res = client
        .get(format!("{}/mail/api_msg_100", bound_url))
        .basic_auth("api_test_user", Some("secure_password"))
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200, "Failed to retrieve email via subprocess");

    // Test C: Verify strict security headers are present from the middleware layer
    // Extract them into owned strings so the borrow on `res` ends immediately
    let h_content_type = res
        .headers()
        .get("x-content-type-options")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let h_frame = res
        .headers()
        .get("x-frame-options")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let h_hsts = res
        .headers()
        .get("strict-transport-security")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    assert_eq!(h_content_type, "nosniff");
    assert_eq!(h_frame, "DENY");
    assert_eq!(h_hsts, "max-age=63072000; includeSubDomains");

    // Now safely consume the body
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["message_id"], "api_msg_100");
    assert_eq!(body["content"], "This is the payload");

    // 3. Gracefully kill the child process to prevent dangling daemons
    child.kill().expect("Failed to kill Lume child process");
    child.wait().expect("Failed to wait on Lume child process");
}
