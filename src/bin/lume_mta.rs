use lume::{security::secure_process, storage::MailHeader, LumeEngine};
use regex::Regex;
use reqwest::Client;
use samotop::mail::{
    AddRecipientResult, Configuration, MailDispatch, MailGuard, MailSetup, Recipient,
    StartMailResult,
};
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
