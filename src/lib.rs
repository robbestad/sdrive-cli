use std::path::PathBuf;

pub mod cli;
pub mod config;
pub mod encryption;
pub mod file;
pub mod fingerprint;
pub mod ipfs;
pub mod p2p;
pub mod parse;
pub mod secret;
pub mod server;
pub mod upload;
#[derive(Debug, Clone)]
pub struct DownloadArgsStruct {
    pub output: Option<PathBuf>,
    pub key: Option<String>,
    pub filename: String,
    pub filepath: String,
}
