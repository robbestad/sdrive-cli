use anyhow::Result;
use clap::Parser;
use reqwest::Client;
use sdrive::{
    cli::{Cli, Commands, ConfigSubcommands, DecryptSource},
    config::{generate_and_save_key, get_config_path, prompt_and_save_config},
    encryption::{decrypt_file, DecryptedData},
    upload::process_upload,
};
use serde_json::Value;
use std::path::PathBuf;
use tokio::fs;
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Upload(args) => {
            let config_path = args.config_path.or_else(get_config_path);
            process_upload(
                args.path.clone(),
                args.path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
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
        },
        Commands::Decrypt(args) => {
            let client = Client::new();

            // Håndter kilde (lokal fil eller URL) og hent encrypted_data
            let (encrypted_data, original_filename) = match args.source {
                DecryptSource::File { path } => {
                    let data = fs::read(&path).await?;
                    let filename = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.trim_end_matches(".enc").to_string()) // Fjern .enc hvis tilstede
                        .unwrap_or_else(|| "decrypted".to_string());
                    (data, filename)
                }
                DecryptSource::Url { url } => {
                    let parsed_url = Url::parse(&url)?;
                    let host = parsed_url.host_str().unwrap_or("");
                    let data = {
                        let response = client.get(&url).send().await?;
                        if !response.status().is_success() {
                            return Err(anyhow::anyhow!(
                                "Failed to download file: {}",
                                response.status()
                            ));
                        }
                        response.bytes().await?.to_vec()
                    };

                    let filename = match host {
                        "cdn.sdrive.pro" => parsed_url
                            .path_segments()
                            .and_then(|segments| segments.last())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| "decrypted".to_string()),
                        "ipfs.sdrive.pro" => {
                            let guid = parsed_url
                                .path_segments()
                                .and_then(|mut segments| segments.nth(1)) // Etter "ipfs"
                                .ok_or_else(|| anyhow::anyhow!("Missing GUID in IPFS URL"))?;
                            let api_url = format!("https://api.sdrive.app/v1/files?guid={}", guid);
                            let response = client.get(&api_url).send().await?;
                            if !response.status().is_success() {
                                return Err(anyhow::anyhow!(
                                    "Failed to fetch file metadata: {}",
                                    response.status()
                                ));
                            }
                            let json: Value = response.json().await?;
                            json.get("filename")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "decrypted".to_string())
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "URL must be from cdn.sdrive.pro or ipfs.sdrive.pro"
                            ))
                        }
                    };
                    (data, filename)
                }
            };

            // Bestem utdatafilnavn basert på originalt filnavn
            let output_path = args.output.unwrap_or_else(|| {
                let mut path = PathBuf::from(original_filename);
                if path.extension().is_none() && !path.to_string_lossy().ends_with(".decrypted") {
                    path.set_extension("decrypted");
                }
                path
            });

            // Lag en midlertidig fil for dekryptering
            let temp_file =
                std::env::temp_dir().join(format!("sdrive_decrypt_{}.enc", rand::random::<u64>()));
            fs::write(&temp_file, &encrypted_data).await?;

            // Dekrypter filen
            let decrypted: DecryptedData<Vec<u8>> = decrypt_file(&temp_file, Some(&output_path))?;
            fs::remove_file(&temp_file).await?;

            match decrypted {
                DecryptedData::Raw(_) => {
                    println!("File decrypted successfully to {}", output_path.display())
                }
                DecryptedData::Structured(_) => unreachable!("Expected raw bytes"),
            }
        }
        Commands::Sync(_args) => {
            println!("Sync command not implemented yet.");
        }
    }
    Ok(())
}
