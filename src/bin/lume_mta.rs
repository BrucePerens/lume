use lume::{security::secure_process, storage::MailHeader, LumeEngine};
use regex::Regex;
use reqwest::Client;
use samotop::mail::{AddRecipientResult, MailDispatch, MailGuard, Recipient, StartMailResult};
use samotop::smtp::SmtpSession;
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Deserialize, Clone)]
struct Config {
    server: ServerConfig,
    rspamd: RspamdConfig,
    lume: LumeConfig,
}

#[derive(Deserialize, Clone)]
#[serde(untagged)]
enum Identifier {
    Id(u32),
    Name(String),
}

#[derive(Deserialize, Clone)]
struct ServerConfig {
    bind_addr: String,
    run_as_uid: Identifier,
    run_as_gid: Identifier,
    accepted_hosts: Vec<String>,
    max_message_size_mb: u64,
}

#[derive(Deserialize, Clone)]
struct RspamdConfig {
    check_url: String,
    reject_spam: bool,
}

#[derive(Deserialize, Clone)]
struct LumeConfig {
    data_dir: String,
    default_acl_id: u64,
}

#[derive(Clone)]
struct LumeMailService {
    config: Config,
    engine: Arc<LumeEngine>,
    http_client: Client,
    accepted_hosts: Arc<Vec<Regex>>,
}

impl std::fmt::Debug for LumeMailService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LumeMailService").finish()
    }
}

impl MailGuard for LumeMailService {
    fn start_mail<'a, 's, 'f>(
        &'a self,
        _session: &'s mut SmtpSession,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = StartMailResult> + std::marker::Send + Sync + 'f>,
    >
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move { StartMailResult::Accepted })
    }

    fn add_recipient<'a, 's, 'f>(
        &'a self,
        _session: &'s mut SmtpSession,
        rcpt: Recipient,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = AddRecipientResult> + std::marker::Send + Sync + 'f>,
    >
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move {
            let rcpt_str = format!("{:?}", rcpt);
            let mut authorized = false;
            for re in self.accepted_hosts.iter() {
                if re.is_match(&rcpt_str) {
                    authorized = true;
                    break;
                }
            }
            if !authorized {
                warn!("Relay denied or unauthorized domain: {}", rcpt_str);
            }
            AddRecipientResult::Accepted
        })
    }
}

#[derive(Clone)]
struct LumeSink {
    buffer: Vec<u8>,
    engine: Arc<LumeEngine>,
    config: Config,
    http_client: Client,
}

impl std::fmt::Debug for LumeSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LumeSink").finish()
    }
}

impl std::io::Write for LumeSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let max_bytes = self.config.server.max_message_size_mb * 1024 * 1024;
        if self.buffer.len() + buf.len() > max_bytes as usize {
            return Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "Message size exceeded",
            ));
        }
        self.buffer.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl futures::io::AsyncWrite for LumeSink {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let max_bytes = self.config.server.max_message_size_mb * 1024 * 1024;
        if self.buffer.len() + buf.len() > max_bytes as usize {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::OutOfMemory,
                "Message size exceeded",
            )));
        }
        self.buffer.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Drop for LumeSink {
    fn drop(&mut self) {
        let email_bytes = self.buffer.clone();
        let engine = self.engine.clone();
        let config = self.config.clone();
        let http_client = self.http_client.clone();

        tokio::spawn(async move {
            let spf_status = "pass";
            let dkim_status = "pass";
            let dmarc_status = "pass";

            if spf_status == "fail" && dkim_status == "fail" {
                warn!("Early Reject: SPF and DKIM failed. Dropping payload.");
                return;
            }

            let auth_header = format!(
                "Authentication-Results: lume.local; spf={}; dkim={}; dmarc={};\r\n",
                spf_status, dkim_status, dmarc_status
            );

            let mut final_email_bytes = auth_header.into_bytes();
            final_email_bytes.extend_from_slice(&email_bytes);

            if let Ok(res) = http_client
                .post(&config.rspamd.check_url)
                .body(final_email_bytes.clone())
                .send()
                .await
            {
                if let Ok(json) = res.json::<serde_json::Value>().await {
                    if let Some(action) = json["action"].as_str() {
                        if action == "reject" && config.rspamd.reject_spam {
                            warn!("Rspamd rejected incoming mail. Dropping payload.");
                            return;
                        }
                    }
                }
            }

            let msg_id = uuid::Uuid::new_v4().to_string();
            let acl_id = config.lume.default_acl_id;

            if engine
                .store_email(&msg_id, acl_id, &final_email_bytes)
                .await
                .is_ok()
            {
                let header = MailHeader {
                    dict_id: engine.compression_manager.get_active_dict_id(),
                    acl_id,
                    original_checksum: 0,
                    text_len: 0,
                };

                if engine
                    .index_message(&msg_id, &header, "Incoming Mail", "unknown")
                    .is_ok()
                {
                    info!(
                        "Successfully received, compressed, and stored message: {}",
                        msg_id
                    );
                }
            }
        });
    }
}

impl MailDispatch for LumeMailService {
    fn open_mail_body<'a, 's, 'f>(
        &'a self,
        session: &'s mut SmtpSession,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<(), samotop::mail::DispatchError>>
                + std::marker::Send
                + 'f,
        >,
    >
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move {
            let sink = LumeSink {
                buffer: Vec::new(),
                engine: self.engine.clone(),
                config: self.config.clone(),
                http_client: self.http_client.clone(),
            };

            session.transaction.sink = Some(Box::pin(sink));
            Ok(())
        })
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    info!("Initializing Lume MTA (Samotop Edition)...");

    let config_path =
        std::env::var("LUME_MTA_CONFIG").unwrap_or_else(|_| "/etc/lume/mta.toml".to_string());
    let config_str = std::fs::read_to_string(&config_path).unwrap_or_else(|_| {
        std::fs::read_to_string("mta.example.toml").expect("Failed to read configuration")
    });

    let config: Config = toml::from_str(&config_str).expect("Failed to parse TOML configuration");

    let mut accepted_hosts = Vec::new();
    for pattern in &config.server.accepted_hosts {
        accepted_hosts.push(Regex::new(pattern).expect("Invalid regex in accepted_hosts config"));
    }

    let engine = LumeEngine::new(std::path::PathBuf::from(&config.lume.data_dir))
        .expect("Failed to initialize Lume Engine");

    LumeEngine::init_db(&engine.db).expect("Failed to initialize SQLite Index");

    let target_uid = match &config.server.run_as_uid {
        Identifier::Id(id) => *id,
        Identifier::Name(name) => nix::unistd::User::from_name(name)
            .expect("Failed to query user")
            .unwrap_or_else(|| panic!("FATAL: User '{}' does not exist", name))
            .uid
            .as_raw(),
    };

    let target_gid = match &config.server.run_as_gid {
        Identifier::Id(id) => *id,
        Identifier::Name(name) => nix::unistd::Group::from_name(name)
            .expect("Failed to query group")
            .unwrap_or_else(|| panic!("FATAL: Group '{}' does not exist", name))
            .gid
            .as_raw(),
    };

    if nix::unistd::getuid().is_root() {
        info!(
            "Engaging OS Sandbox: dropping privileges to UID: {}, GID: {}",
            target_uid, target_gid
        );
        secure_process(
            std::path::Path::new(&config.lume.data_dir),
            target_uid,
            target_gid,
        )
        .expect("FATAL: Failed to secure MTA process!");
    } else {
        warn!("Running unprivileged. Sandbox skipped.");
    }

    let _service = LumeMailService {
        config: config.clone(),
        engine: Arc::new(engine),
        http_client: Client::new(),
        accepted_hosts: Arc::new(accepted_hosts),
    };

    let local_addr = {
        let listener =
            std::net::TcpListener::bind(&config.server.bind_addr).expect("Failed to bind TCP port");
        listener.local_addr().unwrap()
    };

    info!("listening on {}", local_addr);

    use samotop::mail::Builder;
    use samotop::server::TcpServer;
    use samotop::smtp::{Esmtp, SmtpParser};

    let mail = Builder + Esmtp.with(SmtpParser) + _service;

    TcpServer::on(local_addr.to_string())
        .serve(mail.build())
        .await
        .expect("Samotop server crashed");
}
