use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use sdrive::{
    DownloadArgsStruct,
    cli::{Cli, Commands, ConfigSubcommands},
    config::{generate_and_save_key, prompt_and_save_config, read_config},
    encryption::{decrypt_file, export_key, import_key, DecryptedData},
    ipfs::download_file_from_ipfs,
    p2p::{download_file_from_iroh, share_file},
    secret::get_config_path,
    server::start_server,
    upload::process_upload,
};
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::{EnvFilter, FmtSubscriber};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_level = cli.log_level.unwrap_or_else(|| "error".to_string());

    let subscriber = FmtSubscriber::builder()
        .with_env_filter(EnvFilter::new(log_level))
        .finish();  

    tracing::subscriber::set_global_default(subscriber).expect("Setting default subscriber failed");

    match cli.command {
        Commands::Upload(args) => {
            let config_path = args.config_path.or_else(get_config_path);
            process_upload(
                args.path.clone(),
                args.path
                    .parent()
                    .unwrap_or_else(|| Path::new("."))
                    .to_path_buf(),
                config_path.expect("Failed to provide config path"),
                args.unencrypted,
                args.overwrite,
            )
            .await?;
        }
        Commands::Server => {
            start_server().await?;
        }
        Commands::Share(args) => {
            let config = read_config(None).await?;
            share_file(args.path, &config).await?;
        }
        Commands::Config { command } => match command {
            ConfigSubcommands::Create {
                config_path,
                sync_dir,
                api_key,
                user_guid,
            } => {
                prompt_and_save_config(config_path, sync_dir, api_key, user_guid).await?;
            }
            ConfigSubcommands::GenerateKey { config_path } => {
                generate_and_save_key(config_path).await?;
            }
            ConfigSubcommands::ExportKey => {
                let key = export_key().await?;
                println!("Master encryption key (base64): {}", key);
            }
            ConfigSubcommands::ImportKey { key } => {
                import_key(&key)?;
                println!("Master key imported successfully into keyring.");
            }
        },
        Commands::Decrypt(args) => {
            let output_path = args.output.unwrap_or_else(|| {
                let mut path = args.file.clone();
                if path.extension().is_none() {
                    path.set_extension("decrypted");
                }
                path
            });

            let decrypted: DecryptedData<Vec<u8>> =
                decrypt_file(&args.file, Some(&output_path)).await?;
            match decrypted {
                DecryptedData::Raw(_) => println!(
                    "✅ File decrypted successfully to {}",
                    output_path.display()
                ),
                DecryptedData::Structured(_) => unreachable!("Expected raw bytes"),
            }
        }
        Commands::Download(args) => {
            let client = Client::new();
            let config = Arc::new(read_config(None).await?);
            let download_args = DownloadArgsStruct {
                output: args.output.clone(),
                key: args.key.clone(),
                filename: "".to_string(),
                filepath: "".to_string(),
            };
            match args.url.starts_with("blob") {
                true => {
                    download_file_from_iroh(&args.url, &download_args).await?;
                }
                false => {
                    download_file_from_ipfs(&client, &args.url, &download_args, &config).await?;
                }
            }
        }
    }
    Ok(())
}
