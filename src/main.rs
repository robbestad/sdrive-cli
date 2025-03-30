use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::Parser;
use reqwest::Client;
use sdrive::{
    cli::{Cli, Commands, ConfigSubcommands},
    config::{generate_and_save_key, prompt_and_save_config, read_config},
    encryption::{decrypt_file, export_key, import_key, DecryptedData},
    upload::process_upload,
    file::fetch_guid_from_cid,
    secret::get_config_path,
    server::start_server,
};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use url::Url;
use tokio::time::{timeout, Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_level = cli.log_level.unwrap_or_else(|| "info".to_string());

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

            let decrypted: DecryptedData<Vec<u8>> = decrypt_file(&args.file, Some(&output_path)).await?;
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
            let parsed_url = Url::parse(&args.url)?;
            let host = parsed_url.host_str().unwrap_or("");

            if host != "cdn.sdrive.pro" && host != "ipfs.sdrive.pro" {
                return Err(anyhow::anyhow!(
                    "URL must be from cdn.sdrive.pro or ipfs.sdrive.pro"
                ));
            }

            #[allow(unused_assignments)]
            let mut encrypted_data: Option<Vec<u8>> = None;
            #[allow(unused_assignments)]
            let mut original_filename = String::new();

            match host {
                "cdn.sdrive.pro" => {
                    let response = client.get(&args.url).send().await?;
                    if !response.status().is_success() {
                        return Err(anyhow::anyhow!(
                            "Failed to download file: {}",
                            response.status()
                        ));
                    }
                    encrypted_data = Some(response.bytes().await?.to_vec());
                    original_filename = parsed_url
                        .path_segments()
                        .and_then(|segments| segments.last())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "downloaded".to_string());
                }
                "ipfs.sdrive.pro" => {
                    let guid = parsed_url
                        .path_segments()
                        .and_then(|mut segments| segments.nth(1))
                        .ok_or_else(|| anyhow::anyhow!("Missing GUID in IPFS URL"))?;

                    // Step 1: Check local IPFS node
                    // Step 1: Check local IPFS node with POST
                let local_url = "http://localhost:5002/api/v0/cat".to_string();
                match timeout(
                    Duration::from_secs(2),
                    client
                        .post(&local_url)
                        .query(&[("arg", guid)])
                        .send(),
                )
                .await
                {
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        println!("Found {} locally", guid);
                        encrypted_data = Some(resp.bytes().await?.to_vec());
                        original_filename = "downloaded".to_string(); // Default for local
                    }
                        _ => {
                            println!("CID {} not found locally, checking gateway", guid);
                            // Step 2: Fallback to gateway
                            let config_path = Some(get_config_path().expect("Failed to get config path"));
                            let config = read_config(config_path).await?;
                            let api_key = config.api_key.as_str();
                            let response: serde_json::Value = fetch_guid_from_cid(&client, guid, api_key).await?;
                            
                            original_filename = response
                                .get("filename")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "downloaded".to_string());

                            // Fetch the actual file content from the gateway
                            let gateway_url = format!("http://ipfs.sdrive.pro/ipfs/{}", guid);
                            let response = client.get(&gateway_url).send().await?;
                            if !response.status().is_success() {
                                return Err(anyhow::anyhow!(
                                    "Failed to download file from gateway: {}",
                                    response.status()
                                ));
                            }
                            encrypted_data = Some(response.bytes().await?.to_vec());
                        }
                    }
                }
                _ => unreachable!(),
            };

            // Unwrap encrypted_data here since we know it's set
            let encrypted_data = encrypted_data.expect("Encrypted data should be set by now");

            let output_path = args.output.unwrap_or_else(|| {
                let mut path = PathBuf::from(&original_filename);
                if path.extension().is_none() && !path.to_string_lossy().ends_with(".decrypted") {
                    path.set_extension("decrypted");
                }
                path
            });

            if let Some(key) = args.key {
                // Decrypt with per-file key
                if encrypted_data.len() < 72 {
                    return Err(anyhow::anyhow!("Encrypted file too short."));
                }

                let nonce = &encrypted_data[60..72]; // 12 bytes
                let ciphertext = &encrypted_data[72..];

                let per_file_key = STANDARD
                    .decode(&key)
                    .map_err(|_| anyhow::anyhow!("Invalid per-file key (base64)"))?;

                let cipher = Aes256Gcm::new_from_slice(&per_file_key)
                    .map_err(|_| anyhow::anyhow!("Invalid per-file key length"))?;

                let plaintext = cipher
                    .decrypt(Nonce::from_slice(nonce), ciphertext)
                    .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

                fs::write(&output_path, &plaintext).await?;
                println!(
                    "✅ File downloaded and decrypted successfully to {}",
                    output_path.display()
                );
            } else {
                // Use master key from keyring
                let temp_file = std::env::temp_dir()
                    .join(format!("sdrive_download_{}.enc", rand::random::<u64>()));
                fs::write(&temp_file, &encrypted_data).await?;

                let decrypted: DecryptedData<Vec<u8>> =
                    decrypt_file(&temp_file, Some(&output_path)).await?;
                fs::remove_file(&temp_file).await?;

                match decrypted {
                    DecryptedData::Raw(_) => println!(
                        "✅ File downloaded and decrypted successfully to {}",
                        output_path.display()
                    ),
                    DecryptedData::Structured(_) => unreachable!("Expected raw bytes"),
                }
            }
        }
        Commands::Sync(_args) => {
            println!("Sync command not implemented yet.");
        }
    }
    Ok(())
}