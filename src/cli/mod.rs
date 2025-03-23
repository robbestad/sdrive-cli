use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Cli {
    /// Log level: trace, debug, info, warn, error, off
    #[clap(short, long, global = true)]
    pub log_level: Option<String>,
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Config {
        #[clap(subcommand)]
        command: ConfigSubcommands,
    },
    Upload(UploadArgs),
    Sync(SyncArgs),
    Decrypt(DecryptArgs),
    DecryptWithKey(DecryptWithKeyArgs), // Ny kommando fra tidligere
}

#[derive(Subcommand)]
pub enum ConfigSubcommands {
    Create {
        #[clap(short, long)]
        config_path: Option<String>,
        #[clap(short, long)]
        sync_dir: Option<String>,
        #[clap(short, long)]
        user_guid: Option<String>,
        #[clap(short, long)]
        keypair_path: Option<String>,
        #[clap(short, long)]
        api_key: Option<String>,
        #[clap(short, long)]
        rpc_url: Option<String>,
    },
    GenerateKey {
        #[clap(short, long)]
        config_path: Option<String>,
    },
    /// Export the master encryption key from keyring
    ExportKey,
    /// Import a master encryption key into keyring
    ImportKey {
        /// Base64-encoded master key to import
        key: String,
    },
}

#[derive(Args)]
pub struct UploadArgs {
    #[clap(parse(from_os_str))]
    pub path: PathBuf,
    #[clap(short, long)]
    pub config_path: Option<String>,
}

#[derive(Args)]
pub struct SyncArgs {
    #[clap(parse(from_os_str))]
    pub path: PathBuf,
}

#[derive(Args)]
pub struct DecryptArgs {
    #[clap(subcommand)]
    pub source: DecryptSource,
    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum DecryptSource {
    File {
        #[clap(parse(from_os_str))]
        path: PathBuf,
    },
    Url {
        url: String,
    },
}

#[derive(Args)]
pub struct DecryptWithKeyArgs {
    #[clap(parse(from_os_str))]
    pub file: PathBuf,
    #[clap(short, long)]
    pub output: Option<PathBuf>,
    /// Base64-encoded per-file key
    pub key: String,
}