use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(
    author, 
    version, 
    about = "SDrive: A command-line tool for uploading, sharing, and managing files securely on SDrive.\nUse subcommands to upload files, share via P2P, download, or manage configurations.",
    after_help = "EXAMPLES:\n  Upload a file: sdrive upload ./myfile.txt\n  Share a file: sdrive share ./video.mp4\n  Download a file: sdrive download blobacahvuqj... --output video.mp4"
)]
pub struct Cli {
    #[clap(short, long, global = true, help = "Set the logging level (e.g., info, error, debug)")]
    pub log_level: Option<String>,
    #[clap(subcommand)]
    pub command: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
    #[clap(about = "Manage SDrive configuration (create, generate keys, etc.)")]
    Config {
        #[clap(subcommand)]
        command: ConfigSubcommands,
    },
    #[clap(about = "Upload a file to SDrive with optional encryption")]
    Upload(UploadArgs),
    #[clap(about = "Share a file via P2P using Iroh protocol")]
    Share(ShareArgs),
    #[clap(about = "Start the S-Node server")]
    Server,
    #[clap(about = "Download a file from SDrive or Iroh by URL")]
    Download(DownloadArgs),
    #[clap(about = "Decrypt an encrypted file downloaded from SDrive")]
    Decrypt(DecryptArgs),
}

#[derive(Subcommand)]
pub enum ConfigSubcommands {
    #[clap(about = "Create a new SDrive configuration file")]
    Create {
        #[clap(short, long, help = "Path to save the config file")]
        config_path: Option<String>,
        #[clap(short, long, help = "Directory to sync with SDrive")]
        sync_dir: Option<String>,
        #[clap(short, long, help = "User GUID for authentication")]
        user_guid: Option<String>,
        #[clap(short, long, help = "API key for SDrive access")]
        api_key: Option<String>,
    },
    #[clap(about = "Generate a new encryption key and save it")]
    GenerateKey {
        #[clap(short, long, help = "Path to the config file to update")]
        config_path: Option<String>,
    },
    #[clap(about = "Export the current master encryption key")]
    ExportKey,
    #[clap(about = "Import a master encryption key")]
    ImportKey {
        #[clap(help = "The base64-encoded key to import")]
        key: String,
    },
}

#[derive(Args)]
#[clap(
    about = "Share a file using Iroh's P2P protocol.\nThe file will be hashed and made available for download via a unique blob link.",
    after_help = "EXAMPLES:\n  Share a video: sdrive share ./video.mp4\n  Share with custom log level: sdrive share ./video.mp4 -l error"
)]
pub struct ShareArgs {
    /// The file path to share via Iroh P2P
    #[clap(parse(from_os_str), help = "Path to the file you want to share")]
    pub path: PathBuf,
}
// Resten av strukturer (UploadArgs, SyncArgs, etc.) kan også få lignende forbedringer
#[derive(Args)]
pub struct UploadArgs {
    #[clap(parse(from_os_str), help = "Path to the file to upload")]
    pub path: PathBuf,
    #[clap(short, long, help = "Path to the configuration file")]
    pub config_path: Option<String>,
    /// Upload without encryption
    #[clap(long, help = "Skip encryption for this upload")]
    pub unencrypted: bool,
    /// Overwrite existing file
    #[clap(long, help = "Overwrite the file if it already exists on SDrive")]
    pub overwrite: bool,
}

#[derive(Args)]
pub struct DownloadArgs {
    pub url: String,

    #[clap(short, long)]
    pub output: Option<PathBuf>,

    #[clap(short = 'k', long = "key")]
    pub key: Option<String>, // Optional key
}
#[derive(Args)]
pub struct DecryptArgs {
    #[clap(parse(from_os_str))]
    pub file: PathBuf,

    #[clap(short, long)]
    pub output: Option<PathBuf>,
}
