use lume::LumeEngine;
use samotop::mail::{
    AddRecipientFailure, AddRecipientResult, Builder, Configuration, DispatchError, MailDispatch,
    MailGuard, Name, Recipient, StartMailResult,
};
use samotop::server::TcpServer;
use samotop::smtp::SmtpSession;
use serde::Deserialize;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
#[allow(dead_code)]
enum SystemId {
    Int(u32),
    Str(String),
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
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
#[allow(dead_code)]
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
#[allow(dead_code)]
struct Config {
    server: ServerConfig,
    rspamd: RspamdConfig,
    lume: LumeConfig,
}

use tokio::sync::{mpsc, oneshot};

pub struct MailTask {
    pub message_id: String,
    pub buffer: Vec<u8>,
    pub acl_id: u64,
    pub receipt: oneshot::Sender<std::io::Result<()>>,
}

enum SinkState {
    Receiving,
    WaitingForReceipt(oneshot::Receiver<std::io::Result<()>>),
    Done,
}

struct LumeMta {
    config: Arc<Config>,
    engine: Arc<LumeEngine>,
    worker_tx: mpsc::Sender<MailTask>,
}

struct LumeSink {
    buffer: Vec<u8>,
    message_id: String,
    acl_id: u64,
    rejected: bool,
    state: SinkState,
    worker_tx: mpsc::Sender<MailTask>,
}

impl std::fmt::Debug for LumeMta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LumeMta").finish()
    }
}

impl samotop::mail::MailSetup<Configuration> for LumeMta {
    fn setup(self, config: &mut Configuration) {
        use samotop::mail::{AcceptsDispatch, AcceptsGuard};

        let guard_instance = LumeMta {
            config: self.config.clone(),
            engine: self.engine.clone(),
            worker_tx: self.worker_tx.clone(),
        };

        config.add_last_guard(guard_instance);
        config.add_last_dispatch(self);
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
        recipient: Recipient,
    ) -> Pin<Box<dyn Future<Output = AddRecipientResult> + Send + Sync + 'f>>
    where
        'a: 'f,
        's: 'f,
    {
        Box::pin(async move {
            let rcpt_addr = recipient.address.to_string();
            let mut is_accepted = false;

            if let Some(domain) = rcpt_addr.split('@').next_back() {
                let clean_domain = domain.trim_matches(|c| c == '>' || c == '<');
                for host_regex in &self.config.server.accepted_hosts {
                    if let Ok(re) = regex::Regex::new(host_regex) {
                        if re.is_match(clean_domain) {
                            is_accepted = true;
                            break;
                        }
                    }
                }
            }

            if is_accepted {
                AddRecipientResult::Inconclusive(recipient)
            } else {
                AddRecipientResult::Failed(
                    AddRecipientFailure::RejectedPermanently,
                    "Relay access denied".to_string(),
                )
            }
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
        let message_id = session.transaction.id.clone();
        let acl_id = self.config.lume.default_acl_id;
        let worker_tx = self.worker_tx.clone();

        Box::pin(async move {
            let sink = LumeSink {
                buffer: Vec::new(),
                message_id,
                acl_id,
                rejected: false,
                state: SinkState::Receiving,
                worker_tx,
            };
            session.transaction.sink = Some(Box::pin(sink));
            Ok(())
        })
    }
}

impl futures::io::AsyncWrite for LumeSink {
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

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match &mut self.state {
                SinkState::Receiving => {
                    let content_str = String::from_utf8_lossy(&self.buffer);

                    if !content_str.contains("From:") || !content_str.contains("To:") {
                        self.rejected = true;
                        self.state = SinkState::Done;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "550 5.7.1 Message rejected: missing mandatory From or To headers",
                        )));
                    }

                    if self.buffer.is_empty() {
                        self.state = SinkState::Done;
                        return Poll::Ready(Ok(()));
                    }

                    let (receipt_tx, receipt_rx) = oneshot::channel();

                    let task = MailTask {
                        message_id: self.message_id.clone(),
                        buffer: std::mem::take(&mut self.buffer),
                        acl_id: self.acl_id,
                        receipt: receipt_tx,
                    };

                    if self.worker_tx.try_send(task).is_err() {
                        self.state = SinkState::Done;
                        return Poll::Ready(Err(std::io::Error::other(
                            "450 4.3.2 System heavily loaded, please try again",
                        )));
                    }

                    self.state = SinkState::WaitingForReceipt(receipt_rx);
                }
                SinkState::WaitingForReceipt(rx) => match std::pin::Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(Ok(()))) => {
                        self.state = SinkState::Done;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(Err(e))) => {
                        self.state = SinkState::Done;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Ready(Err(_)) => {
                        self.state = SinkState::Done;
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "450 4.3.0 Internal storage worker failed",
                        )));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                SinkState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt::init();

    let config_path =
        std::env::var("LUME_MTA_CONFIG").unwrap_or_else(|_| "mta.example.toml".to_string());
    tracing::info!("Loading config from {}", config_path);
    let config_data = std::fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&config_data)?;

    let engine = LumeEngine::new(std::path::PathBuf::from(&config.lume.data_dir))?;
    LumeEngine::init_db(&engine.db)?;

    let engine_arc = std::sync::Arc::new(engine);
    let config_arc = std::sync::Arc::new(config);

    // 1. Create the cross-runtime channel
    let (worker_tx, mut worker_rx) = mpsc::channel::<MailTask>(1000);
    let worker_engine = engine_arc.clone();

    // 2. Spawn the Tokio Background Worker
    tokio::spawn(async move {
        while let Some(task) = worker_rx.recv().await {
            let engine = worker_engine.clone();

            let db_result = tokio::time::timeout(std::time::Duration::from_secs(10), async move {
                if let Ok(_path) = engine
                    .store_email(&task.message_id, task.acl_id, &task.buffer)
                    .await
                {
                    let header = lume::storage::MailHeader {
                        dict_id: engine.compression_manager.get_active_dict_id(),
                        acl_id: task.acl_id,
                        original_checksum: 0,
                        text_len: 0,
                    };
                    let _ = engine.index_message(
                        &task.message_id,
                        &header,
                        "MTA Integration Test",
                        "sender@test.com",
                    );
                    Ok(())
                } else {
                    Err(std::io::Error::other("Database storage failed"))
                }
            })
            .await;

            let final_response = match db_result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "450 4.4.2 Storage timeout",
                )),
            };

            let _ = task.receipt.send(final_response);
        }
    });

    let mta = LumeMta {
        config: config_arc.clone(),
        engine: engine_arc.clone(),
        worker_tx,
    };

    let bind_addr = &config_arc.server.bind_addr;
    let actual_addr = {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        listener.local_addr()?
    };

    println!("listening on {}", actual_addr);
    tracing::info!("listening on {}", actual_addr);

    let mail_service = Builder
        .using(samotop::smtp::Esmtp.with(samotop::smtp::SmtpParser))
        .using(Name::new("lume"))
        .using(mta)
        .build();

    TcpServer::on(actual_addr).serve(mail_service).await?;

    Ok(())
}
