use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(author, version, about)]
pub struct Cli {
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
    DownloadWithKey(DownloadWithKeyArgs),
    Download(DownloadArgs),
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
    ExportKey,
    ImportKey {
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
pub struct DownloadArgs {
    pub url: String,  

    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct DecryptArgs {
    #[clap(parse(from_os_str))]
    pub file: PathBuf,

    #[clap(short, long)]
    pub output: Option<PathBuf>,
}

#[derive(Args)]
pub struct DownloadWithKeyArgs {
    pub url: String,

    #[clap(short = 'k', long = "key")]
    pub key: String,

    #[clap(short, long)]
    pub output: Option<PathBuf>,
}