use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use lume::LumeEngine;

#[tokio::test]
async fn test_mta_daemon_via_subprocess() {
    // 1. Set up a secure, isolated temporary environment
    let test_dir = std::env::temp_dir().join(format!("lume_mta_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&test_dir).unwrap();

    let data_dir = test_dir.join("data");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Dynamically generate a TOML configuration for the test daemon
    let config_path = test_dir.join("mta.example.toml");
    let config_content = format!(
        r#"
[server]
bind_addr = "127.0.0.1:0"
run_as_uid = 1000
run_as_gid = 1000
accepted_hosts = ["example\\.com$"]
max_connections = 10
idle_timeout_secs = 5
max_message_size_mb = 1

[rspamd]
check_url = "http://127.0.0.1:9999/checkv2"
reject_spam = true

[lume]
data_dir = "{}"
default_acl_id = 1
"#,
        data_dir.display().to_string().replace('\\', "/")
    );
    std::fs::write(&config_path, config_content).unwrap();

    // 2. Spawn the MTA daemon as a child process
    let mut child = Command::new(env!("CARGO_BIN_EXE_lume_mta"))
        .env("LUME_MTA_CONFIG", config_path.to_str().unwrap())
        .current_dir(&test_dir) // Force fallback to our localized mta.example.toml
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to start Lume MTA daemon");

    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let mut bound_port = 0;

    // 3. Wait for the daemon to dynamically bind and announce its port
    for _ in 0..50 {
        line.clear();
        if reader.read_line(&mut line).unwrap() > 0 {
            if line.contains("listening on ") {
                let parts: Vec<&str> = line.trim().split(':').collect();
                if let Some(port_str) = parts.last() {
                    bound_port = port_str.parse().unwrap_or(0);
                }
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(
        bound_port > 0,
        "MTA Daemon failed to start or report its port"
    );

    // 4. Connect via TCP and test the SMTP protocol interactions
    let mut stream = TcpStream::connect(format!("127.0.0.1:{}", bound_port))
        .await
        .unwrap();
    let mut buf = vec![0; 1024];

    let n = stream.read(&mut buf).await.unwrap();
    let greeting = String::from_utf8_lossy(&buf[..n]).to_lowercase();
    assert!(
        greeting.contains("220 lume service ready"),
        "Server greeting mismatch! Actually received from Samotop: '{}'",
        greeting
    );

    stream.write_all(b"EHLO localhost\r\n").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let ehlo_response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        ehlo_response.contains("250 lume"),
        "EHLO response mismatch! Actually received from Samotop: '{}'",
        ehlo_response
    );

    // --- TEST A: Relay Protection ---
    stream
        .write_all(b"MAIL FROM:<attacker@evil.com>\r\n")
        .await
        .unwrap();
    let _ = stream.read(&mut buf).await.unwrap();

    stream
        .write_all(b"RCPT TO:<target@unauthorized.com>\r\n")
        .await
        .unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("550"),
        "MTA failed to reject unauthorized relay domain! Actually received: '{}'",
        response
    );

    // --- TEST B: Header Sanity Enforcement ---
    stream
        .write_all(b"MAIL FROM:<sender@test.com>\r\n")
        .await
        .unwrap();
    let _ = stream.read(&mut buf).await.unwrap();

    stream
        .write_all(b"RCPT TO:<valid@example.com>\r\n")
        .await
        .unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("250"),
        "Expected 250 Ok for valid recipient! Actually received: '{}'",
        response
    );

    stream.write_all(b"DATA\r\n").await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("354"),
        "Expected 354 Start mail input! Actually received: '{}'",
        response
    );

    stream
        .write_all(b"Subject: Missing From and To\r\n\r\nBad payload\r\n.\r\n")
        .await
        .unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("450"),
        "MTA failed to reject malformed body! Actually received: '{}'",
        response
    );

    // --- TEST C: Successful Delivery & Atomic Storage ---
    stream
        .write_all(b"MAIL FROM:<sender@test.com>\r\n")
        .await
        .unwrap();
    let _ = stream.read(&mut buf).await.unwrap();

    stream
        .write_all(b"RCPT TO:<valid@example.com>\r\n")
        .await
        .unwrap();
    let _ = stream.read(&mut buf).await.unwrap();

    stream.write_all(b"DATA\r\n").await.unwrap();
    let _ = stream.read(&mut buf).await.unwrap();

    let valid_email = b"From: sender@test.com\r\nTo: valid@example.com\r\nSubject: MTA Integration Test\r\n\r\nThis is a securely transmitted message.\r\n.\r\n";
    stream.write_all(valid_email).await.unwrap();
    let n = stream.read(&mut buf).await.unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(
        response.contains("250") && response.to_lowercase().contains("queued"),
        "MTA failed to accept and store valid email! Actually received: '{}'",
        response
    );

    stream.write_all(b"QUIT\r\n").await.unwrap();
    let _ = stream.read(&mut buf).await.unwrap();

    // 5. Gracefully kill the daemon to free locks
    child.kill().expect("Failed to kill Lume MTA child process");
    child
        .wait()
        .expect("Failed to wait on Lume MTA child process");

    // 6. Verify the email was successfully stored and indexed in Lume
    let engine = LumeEngine::new(data_dir.clone()).expect("Failed to open LumeEngine");
    let matches = engine
        .search_by_subject(1, "MTA Integration Test")
        .expect("Failed to search SQLite index");

    assert_eq!(matches.len(), 1, "Email was not indexed correctly");

    let content = engine
        .get_email(&matches[0])
        .await
        .expect("Failed to fetch email payload from disk");

    let content_str = String::from_utf8_lossy(&content);
    assert!(
        content_str.contains("This is a securely transmitted message."),
        "Payload was corrupted during MTA transfer! Actually received: '{}'",
        content_str
    );

    // Cleanup
    let _ = std::fs::remove_dir_all(&test_dir);
}
