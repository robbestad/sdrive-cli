use clap::Parser;
use sdrive::{
    cli::{Cli, Commands, ConfigSubcommands},
    config::{generate_and_save_key, get_config_path, prompt_and_save_config},
    encryption::{decrypt_file, export_key, import_key, export_per_file_key, DecryptedData},
    upload::process_upload,
};
use std::path::{Path, PathBuf};
use reqwest::Client;
use tokio::fs;
use url::Url;
use anyhow::Result;
use tracing_subscriber::{FmtSubscriber, EnvFilter};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce}; // Importerer Nonce
use base64::{Engine as _, engine::general_purpose::STANDARD};

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
            )
            .await?;
        }
        Commands::Config { command } => match command {
            ConfigSubcommands::Create {
                config_path,
                rpc_url,
                sync_dir,
                api_key,
                user_guid,
                keypair_path,
            } => {
                prompt_and_save_config(
                    config_path,
                    rpc_url,
                    sync_dir,
                    api_key,
                    user_guid,
                    keypair_path,
                )
                .await?;
            }
            ConfigSubcommands::GenerateKey { config_path } => {
                generate_and_save_key(config_path).await?;
            }
            ConfigSubcommands::ExportKey => {
                let key = export_key()?;
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

            let decrypted: DecryptedData<Vec<u8>> = decrypt_file(&args.file, Some(&output_path))?;
            match decrypted {
                DecryptedData::Raw(_) => println!("✅ File decrypted successfully to {}", output_path.display()),
                DecryptedData::Structured(_) => unreachable!("Expected raw bytes"),
            }
        }
        Commands::Download(args) => {
            let client = Client::new();
            let parsed_url = Url::parse(&args.url)?;
            let host = parsed_url.host_str().unwrap_or("");
        
            // Valider host før nedlasting
            if host != "cdn.sdrive.pro" && host != "ipfs.sdrive.pro" {
                return Err(anyhow::anyhow!("URL must be from cdn.sdrive.pro or ipfs.sdrive.pro"));
            }
        
            let response = client.get(&args.url).send().await?;
            if !response.status().is_success() {
                return Err(anyhow::anyhow!("Failed to download file: {}", response.status()));
            }
            let encrypted_data = response.bytes().await?.to_vec();
        
            let temp_file = std::env::temp_dir().join(format!("sdrive_download_{}.enc", rand::random::<u64>()));
            fs::write(&temp_file, &encrypted_data).await?;
            let _per_file_key = export_per_file_key(&temp_file)?;
        
            let original_filename = match host {
                "cdn.sdrive.pro" => {
                    parsed_url.path_segments()
                        .and_then(|segments| segments.last())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "decrypted".to_string())
                }
                "ipfs.sdrive.pro" => {
                    let guid = parsed_url.path_segments()
                        .and_then(|mut segments| segments.nth(1))
                        .ok_or_else(|| anyhow::anyhow!("Missing GUID in IPFS URL"))?;
        
                    let api_url = format!("https://api.sdrive.app/v1/files?guid={}", guid);
                    let response = client.get(&api_url).send().await?;
                    if !response.status().is_success() {
                        return Err(anyhow::anyhow!("Failed to fetch file metadata: {}", response.status()));
                    }
        
                    let json: serde_json::Value = response.json().await?;
                    json.get("filename")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "decrypted".to_string())
                }
                _ => unreachable!(),
            };
        
            let output_path = args.output.unwrap_or_else(|| {
                let mut path = PathBuf::from(&original_filename);
                if path.extension().is_none() && !path.to_string_lossy().ends_with(".decrypted") {
                    path.set_extension("decrypted");
                }
                path
            });
        
            let decrypted: DecryptedData<Vec<u8>> = decrypt_file(&temp_file, Some(&output_path))?;
            fs::remove_file(&temp_file).await?;
        
            match decrypted {
                DecryptedData::Raw(_) => println!("✅ File downloaded and decrypted successfully to {}", output_path.display()),
                DecryptedData::Structured(_) => unreachable!("Expected raw bytes"),
            }
        }
        Commands::DownloadWithKey(args) => {
            let client = Client::new();
            let parsed_url = Url::parse(&args.url)?;
            let host = parsed_url.host_str().unwrap_or("");

            if host != "cdn.sdrive.pro" && host != "ipfs.sdrive.pro" {
                return Err(anyhow::anyhow!("URL must be from cdn.sdrive.pro or ipfs.sdrive.pro"));
            }

            let response = client.get(&args.url).send().await?;
            if !response.status().is_success() {
                return Err(anyhow::anyhow!("Failed to download file: {}", response.status()));
            }

            let encrypted_data = response.bytes().await?.to_vec();

            let original_filename = match host {
                "cdn.sdrive.pro" => {
                    parsed_url.path_segments()
                        .and_then(|segments| segments.last())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "downloaded".to_string())
                }
                "ipfs.sdrive.pro" => {
                    let guid = parsed_url.path_segments()
                        .and_then(|mut segments| segments.nth(1))
                        .ok_or_else(|| anyhow::anyhow!("Missing GUID in IPFS URL"))?;

                    let api_url = format!("https://api.sdrive.app/v1/files?guid={}", guid);
                    let response = client.get(&api_url).send().await?;
                    if !response.status().is_success() {
                        return Err(anyhow::anyhow!("Failed to fetch file metadata: {}", response.status()));
                    }

                    let json: serde_json::Value = response.json().await?;
                    json.get("filename")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "downloaded".to_string())
                }
                _ => unreachable!(),
            };

            let output_path = args.output.unwrap_or_else(|| {
                let mut path = PathBuf::from(&original_filename);
                if path.extension().is_none() && !path.to_string_lossy().ends_with(".decrypted") {
                    path.set_extension("decrypted");
                }
                path
            });

            // Filformat: [encrypted_key (48)][key_nonce (12)][nonce (12)][ciphertext]
            if encrypted_data.len() < 72 {
                return Err(anyhow::anyhow!("Encrypted file too short."));
            }

            let nonce = &encrypted_data[60..72]; // 12 bytes
            let ciphertext = &encrypted_data[72..];

            let per_file_key = STANDARD.decode(&args.key)
                .map_err(|_| anyhow::anyhow!("Invalid per-file key (base64)"))?;

            let cipher = Aes256Gcm::new_from_slice(&per_file_key)
                .map_err(|_| anyhow::anyhow!("Invalid per-file key length"))?;

            // Spesifiser Nonce-typen eksplisitt for Aes256Gcm
            let plaintext = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

            fs::write(&output_path, &plaintext).await?;

            println!("✅ File downloaded and decrypted successfully to {}", output_path.display());
        }
        Commands::Sync(_args) => {
            println!("Sync command not implemented yet.");
        }
    }
    Ok(())
}