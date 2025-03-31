use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[clap(
    author, 
    version, 
    about = "SDrive: A command-line tool for uploading, sharing, and managing files securely on SDrive.\nUse subcommands to upload files, share via P2P, download, or manage configurations.",
    after_help = "EXAMPLES:\n  Upload a file: sdrive upload ./myfile.txt\n  Share a file: sdrive share ./video.mp4\n  Download a file: sdrive download blobacahvuqj... --output video.mp4\n  Start server: sdrive server\n  Decrypt file: sdrive decrypt encrypted.bin --output decrypted.txt"
)]
pub struct Cli {
    #[clap(short, long, global = true, help = "Set the logging level (e.g., info, error, debug). Default is 'info'")]
    pub log_level: Option<String>,
    #[clap(subcommand)]
    pub command: Commands,
}


#[derive(Subcommand)]
pub enum Commands {
    #[clap(about = "Manage SDrive configuration (create, generate keys, etc.)", after_help = "EXAMPLES:\n  Create config: sdrive config create --config-path ./config.toml\n  Generate key: sdrive config generate-key\n  Export key: sdrive config export-key\n  Import key: sdrive config import-key <base64-key>")]
    Config {
        #[clap(subcommand)]
        command: ConfigSubcommands,
    },
    #[clap(about = "Upload a file to SDrive with optional encryption", after_help = "EXAMPLES:\n  Upload with encryption: sdrive upload ./secret.txt\n  Upload without encryption: sdrive upload ./public.txt --unencrypted\n  Upload with custom config: sdrive upload ./file.txt --config-path ./custom.toml\n  Force upload: sdrive upload ./file.txt --overwrite")]
    Upload(UploadArgs),
    #[clap(about = "Share a file via P2P using Iroh protocol", after_help = "EXAMPLES:\n  Share a file: sdrive share ./video.mp4\n  Share with custom log level: sdrive share ./video.mp4 -l error\n  Share large file: sdrive share ./dataset.zip")]
    Share(ShareArgs),
    #[clap(about = "Start the S-Node server (advanced)", after_help = "EXAMPLES:\n  Start server: sdrive server")]
    Server,
    #[clap(about = "Download a file from SDrive or Iroh by URL", after_help = "EXAMPLES:\n  Download to current directory: sdrive download blobacahvuqj...\n  Download with custom output: sdrive download blobacahvuqj... --output video.mp4\n  Download with decryption key: sdrive download blobacahvuqj... --key <base64-key>")]
    Download(DownloadArgs),
    #[clap(about = "Decrypt an encrypted file downloaded from SDrive", after_help = "EXAMPLES:\n  Decrypt to current directory: sdrive decrypt encrypted.bin\n  Decrypt with custom output: sdrive decrypt encrypted.bin --output decrypted.txt")]
    Decrypt(DecryptArgs),
}

#[derive(Subcommand)]
pub enum ConfigSubcommands {
    #[clap(about = "Create a new SDrive configuration file", after_help = "EXAMPLES:\n  Create with defaults: sdrive config create\n  Create with custom path: sdrive config create --config-path ./config.toml\n  Create with sync directory: sdrive config create --sync-dir ./sdrive-files")]
    Create {
        #[clap(short, long, help = "Path to save the config file (default: ~/.sdrive/config.toml)")]
        config_path: Option<String>,
        #[clap(short, long, help = "Directory to sync with SDrive (default: ~/.sdrive/sync)")]
        sync_dir: Option<String>,
        #[clap(short, long, help = "User GUID for authentication (required for SDrive access)")]
        user_guid: Option<String>,
        #[clap(short, long, help = "API key for SDrive access (required for SDrive access)")]
        api_key: Option<String>,
    },
    #[clap(about = "Generate a new encryption key and save it", after_help = "EXAMPLES:\n  Generate key with default config: sdrive config generate-key\n  Generate key with custom config: sdrive config generate-key --config-path ./config.toml")]
    GenerateKey {
        #[clap(short, long, help = "Path to the config file to update (default: ~/.sdrive/config.toml)")]
        config_path: Option<String>,
    },
    #[clap(about = "Export the current master encryption key", after_help = "EXAMPLES:\n  Export key: sdrive config export-key\n  Export key with custom config: sdrive config export-key --config-path ./config.toml")]
    ExportKey,
    #[clap(about = "Import a master encryption key", after_help = "EXAMPLES:\n  Import key: sdrive config import-key <base64-encoded-key>")]
    ImportKey {
        #[clap(help = "The base64-encoded key to import")]
        key: String,
    },
}

#[derive(Args)]
#[clap(
    about = "Share a file using Iroh's P2P protocol.\nThe file will be hashed and made available for download via a unique blob link.",
    after_help = "EXAMPLES:\n  Share a video: sdrive share ./video.mp4\n  Share with custom log level: sdrive share ./video.mp4 -l error\n  Share large file: sdrive share ./dataset.zip"
)]
pub struct ShareArgs {
    /// The file path to share via Iroh P2P
    #[clap(parse(from_os_str), help = "Path to the file you want to share (supports any file type)")]
    pub path: PathBuf,
}

#[derive(Args)]
#[clap(
    about = "Upload a file to SDrive with optional encryption",
    after_help = "EXAMPLES:\n  Upload with encryption: sdrive upload ./secret.txt\n  Upload without encryption: sdrive upload ./public.txt --unencrypted\n  Upload with custom config: sdrive upload ./file.txt --config-path ./custom.toml\n  Force upload: sdrive upload ./file.txt --overwrite"
)]
pub struct UploadArgs {
    #[clap(parse(from_os_str), help = "Path to the file to upload (supports any file type)")]
    pub path: PathBuf,
    #[clap(short, long, help = "Path to the configuration file (default: ~/.sdrive/config.toml)")]
    pub config_path: Option<String>,
    /// Upload without encryption
    #[clap(long, help = "Skip encryption for this upload (useful for public files)")]
    pub unencrypted: bool,
    /// Overwrite existing file
    #[clap(long, help = "Overwrite the file if it already exists on SDrive (use with caution)")]
    pub overwrite: bool,
}

#[derive(Args)]
#[clap(
    about = "Download a file from SDrive or Iroh by URL",
    after_help = "EXAMPLES:\n  Download to current directory: sdrive download blobacahvuqj...\n  Download with custom output: sdrive download blobacahvuqj... --output video.mp4\n  Download with decryption key: sdrive download blobacahvuqj... --key <base64-key>"
)]
pub struct DownloadArgs {
    #[clap(help = "The SDrive or Iroh URL to download from")]
    pub url: String,

    #[clap(short, long, help = "Output file path (default: uses original filename)")]
    pub output: Option<PathBuf>,

    #[clap(short = 'k', long = "key", help = "Decryption key for encrypted files (base64-encoded)")]
    pub key: Option<String>,
}

#[derive(Args)]
#[clap(
    about = "Decrypt an encrypted file downloaded from SDrive",
    after_help = "EXAMPLES:\n  Decrypt to current directory: sdrive decrypt encrypted.bin\n  Decrypt with custom output: sdrive decrypt encrypted.bin --output decrypted.txt"
)]
pub struct DecryptArgs {
    #[clap(parse(from_os_str), help = "Path to the encrypted file to decrypt")]
    pub file: PathBuf,

    #[clap(short, long, help = "Output file path (default: removes .encrypted extension)")]
    pub output: Option<PathBuf>,
}
