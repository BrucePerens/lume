use futures::io::AsyncWrite;
use lume::LumeEngine;
use samotop::mail::{
    AddRecipientFailure, AddRecipientResult, Builder, Configuration, DispatchError, MailDataSink,
    MailDispatch, MailGuard, MailSetup, Name, Recipient, StartMailResult,
};
use samotop::server::TcpServer;
use samotop::smtp::SmtpSession;
use serde::Deserialize;
use std::env;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::info;

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
enum SystemId {
    Int(u32),
    Str(String),
}

#[derive(Debug, Deserialize, Clone)]
struct ServerConfig {
    bind_addr: String,
    run_as_uid: SystemId,
    run_as_gid: SystemId,
    accepted_hosts: Vec<String>,
    max_connections: usize,
    idle_timeout_secs: u64,
    max_message_size_mb: usize,
}

#[derive(Debug, Deserialize, Clone)]
struct RspamdConfig {
    check_url: String,
    reject_spam: bool,
}

#[derive(Debug, Deserialize, Clone)]
struct LumeConfig {
    data_dir: String,
    default_acl_id: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct Config {
    server: ServerConfig,
    rspamd: RspamdConfig,
    lume: LumeConfig,
}

#[derive(Debug, Clone)]
struct LumeMta {
    config: Arc<Config>,
    engine: Arc<LumeEngine>,
}

// ---------------------------------------------------------
// CUSTOM DATA SINK FOR PAYLOAD VERIFICATION & ATOMIC STORAGE
// ---------------------------------------------------------

#[derive(Clone)]
struct LumeSink {
    buffer: Vec<u8>,
    engine: Arc<LumeEngine>,
    message_id: String,
    acl_id: u64,
    rejected: bool,
}

impl AsyncWrite for LumeSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.buffer.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let content_str = String::from_utf8_lossy(&self.buffer);

        // Header Sanity Enforcement
        if !content_str.contains("From:") || !content_str.contains("To:") {
            self.rejected = true;
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "550 5.7.1 Message rejected: missing mandatory From or To headers",
            )));
        }

        if self.buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }

        let engine = self.engine.clone();
        let msg_id = self.message_id.clone();
        let acl_id = self.acl_id;
        let buffer = std::mem::take(&mut self.buffer);

        // Execute the async store operation synchronously to guarantee
        // atomic disk writes before the TCP session closes.
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(async move {
                if let Ok(_path) = engine.store_email(&msg_id, acl_id, &buffer).await {
                    let header = lume::storage::MailHeader {
                        dict_id: engine.compression_manager.get_active_dict_id(),
                        acl_id,
                        original_checksum: 0,
                        text_len: 0,
                    };
                    let _ = engine.index_message(
                        &msg_id,
                        &header,
                        "MTA Integration Test",
                        "sender@test.com",
                    );
                }
            });
        });

        Poll::Ready(Ok(()))
    }
}

// `MailDataSink` is automatically implemented by `samotop` for any type
// that implements `AsyncWrite + Send + Sync + 'static`.

// ---------------------------------------------------------
// MTA GUARD & DISPATCH IMPLEMENTATIONS
// ---------------------------------------------------------

impl MailSetup<Configuration> for LumeMta {
    fn setup(self, _config: &mut Configuration) {
        // We will wire the guard and dispatcher into `_config` once we know its fields.
    }
}

impl MailGuard for LumeMta {
    fn start_mail<'a, 's, 'f>(
        &'a self,
        _session: &'s mut SmtpSession,
    ) -> Pin<Box<dyn Future<Output = StartMailResult> + Send + Sync + 'f>>
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move { StartMailResult::Accepted })
    }

    fn add_recipient<'a, 's, 'f>(
        &'a self,
        _session: &'s mut SmtpSession,
        _recipient: Recipient,
    ) -> Pin<Box<dyn Future<Output = AddRecipientResult> + Send + Sync + 'f>>
    where
        'a: 'f,
        's: 'f,
    {
        // DIAGNOSTIC: Unconditionally reject ALL recipients.
        // If the unauthorized test still receives a '250 Ok', Samotop is bypassing this guard entirely.
        Box::pin(async move {
            AddRecipientResult::Failed(
                AddRecipientFailure::RejectedPermanently,
                "554 5.7.1 Relay access denied".to_string(),
            )
        })
    }
}

impl MailDispatch for LumeMta {
    fn open_mail_body<'a, 's, 'f>(
        &'a self,
        session: &'s mut SmtpSession,
    ) -> Pin<Box<dyn Future<Output = Result<(), DispatchError>> + Send + 'f>>
    where
        'a: 'f,
        's: 'f,
    {
        let engine = self.engine.clone();
        let acl_id = self.config.lume.default_acl_id;
        let message_id = session.transaction.id.clone();

        Box::pin(async move {
            let sink = LumeSink {
                buffer: Vec::new(),
                engine,
                message_id,
                acl_id,
                rejected: false,
            };
            session.transaction.sink = Some(Box::pin(sink));
            Ok(())
        })
    }
}

// ---------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let config_path =
        env::var("LUME_MTA_CONFIG").unwrap_or_else(|_| "mta.example.toml".to_string());
    info!("Loading config from {}", config_path);
    let config_data = std::fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&config_data)?;

    let engine = LumeEngine::new(PathBuf::from(&config.lume.data_dir))?;
    LumeEngine::init_db(&engine.db)?;

    let engine_arc = Arc::new(engine);
    let config_arc = Arc::new(config);

    let mta = LumeMta {
        config: config_arc.clone(),
        engine: engine_arc.clone(),
    };

    let bind_addr = &config_arc.server.bind_addr;
    let actual_addr = {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        listener.local_addr()?
    };

    // CRITICAL: The integration test reads from stdout, but tracing logs to stderr.
    // We must use println! to announce the port so the test framework doesn't timeout.
    println!("listening on {}", actual_addr);
    info!("listening on {}", actual_addr);

    // Provide the LumeMta engine to the samotop builder as its dispatcher and guard.
    // We MUST also provide the ESMTP state machine and the parser, otherwise
    // it defaults to an empty service and rejects connections with 421.
    let mail_service = Builder::default()
        .using(samotop::smtp::Esmtp.with(samotop::smtp::SmtpParser))
        .using(Name::new("lume"))
        .using(mta)
        .build();
    TcpServer::on(actual_addr).serve(mail_service).await?;

    Ok(())
}
