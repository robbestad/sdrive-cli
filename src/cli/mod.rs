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
    // config
    Config {
        #[clap(subcommand)]
        command: ConfigSubcommands,
    },
    Upload(UploadArgs),
    Sync(SyncArgs),
    Credits {
        #[clap(subcommand)]
        command: CreditsSubcommands,
    },
}

#[derive(Subcommand)]
pub enum ConfigSubcommands {
    /// Interactive process to create a config file
    Create {
        /// Config file path
        #[clap(short, long)]
        config_path: Option<String>,

        /// Sync path
        #[clap(short, long)]
        sync_dir: Option<String>,

        /// User GUID
        #[clap(short, long)]
        user_guid: Option<String>,

        /// Keypair path
        #[clap(short, long)]
        keypair_path: Option<String>,

        /// API key
        #[clap(short, long)]
        api_key: Option<String>,

        /// RPC Url
        #[clap(short, long)]
        rpc_url: Option<String>,
    },
}

#[derive(Args)]
pub struct UploadArgs {
    /// Path to the file or directory to upload
    #[clap(parse(from_os_str))]
    pub path: PathBuf,

    /// Path to the config file
    #[clap(short, long)]
    pub config_path: Option<String>,
}

#[derive(Args)]
pub struct SyncArgs {
    /// Path to the file or directory to store synced data (not implemented yet)
    #[clap(parse(from_os_str))]
    pub path: PathBuf,
}

#[derive(Subcommand)]
pub enum CreditsSubcommands {
    /// Show your credits status
    Status {
        /// Path to the config file
        #[clap(short, long)]
        config_path: Option<String>,
    },

    /// Stake credits
    Stake {
        /// Path to the config file
        #[clap(short, long)]
        config_path: String,

        /// Stake credits
        #[clap(short, long)]
        amount: Option<String>,
    },

    /// Unstake credits
    Unstake {
        /// Path to the config file
        #[clap(short, long)]
        config_path: String,

        /// Unstake
        #[clap(short, long)]
        amount: Option<String>,
    },

    /// Claim credits
    Claim {
        /// Path to the config file
        #[clap(short, long)]
        config_path: String,

        /// Claim
        #[clap(short, long)]
        amount: Option<String>,
    },
}
