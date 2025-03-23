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
    /// Source to decrypt: either a local file path or a URL from cdn.sdrive.pro
    #[clap(subcommand)]
    pub source: DecryptSource,
    /// Optional output file path (defaults to <filename>.decrypted or decrypted_<timestamp>.bin for URLs)
    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum DecryptSource {
    /// Decrypt a local file
    File {
        #[clap(parse(from_os_str))]
        path: PathBuf,
    },
    /// Decrypt a file from a URL (e.g., https://cdn.sdrive.pro/<guid>/<filename>)
    Url { url: String },
}
