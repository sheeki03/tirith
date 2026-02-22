use std::sync::Arc;

use crate::config::Config;
use crate::db::Db;
use crate::sign::TokenSigner;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub signer: Arc<TokenSigner>,
    pub config: Arc<Config>,
    pub http_client: reqwest::Client,
}
