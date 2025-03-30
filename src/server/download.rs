use crate::encryption::{decrypt_file, DecryptedData};
use crate::server::Config;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::time::{timeout, Duration};

pub struct Args {
    pub output: Option<PathBuf>,
    pub key: Option<String>,
    pub filename: String,
    pub filepath: String,
}

pub async fn download_file(
    client: &Client,
    cid: &str,
    args: &Args,
    config: &Arc<Config>,
) -> Result<Vec<u8>> {
    println!("🔑 CID: {}", cid);
    println!("🔑 Encryption key: {:?}", args.key);
    println!("🔑 Filename: {}", args.filename);
    println!("🔑 Filepath: {}", args.filepath);
    println!("🔑 Output: {:?}", args.output);
    println!("🔑 Sync_dir: {}", config.sync_dir);

    let local_url = "http://localhost:5002/api/v0/cat".to_string();
    let response = timeout(
        Duration::from_secs(10),
        client.post(&local_url).query(&[("arg", cid)]).send(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Timeout waiting for IPFS response"))??;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download file from local node: {}",
            response.status()
        ));
    }

    let encrypted_data = response.bytes().await?;
    println!("📏 Encrypted data length: {}", encrypted_data.len());

    let base_dir = PathBuf::from(&config.sync_dir);
    let temp_dir = base_dir.join("temp");
    fs::create_dir_all(&temp_dir).await?; // Opprett temp-katalog hvis den ikke finnes

    let temp_file = temp_dir.join(format!("download_{}_{}", cid, rand::random::<u64>()));
    let output_path = if !args.filepath.is_empty() {
        if args.filepath.starts_with("~/") {
            base_dir.join(args.filepath.trim_start_matches("~/"))
        } else {
            base_dir.join(&args.filepath)
        }
    } else {
        base_dir.join(&args.filename)
    };

    let final_output_path = args.output.clone().unwrap_or(output_path);
    let key = args.key.clone().unwrap_or("".to_string());
    let data = if !key.is_empty() {
        if let Some(key) = &args.key {
            if encrypted_data.len() < 72 {
                return Err(anyhow::anyhow!(
                    "Encrypted file too short (length: {}).",
                    encrypted_data.len()
                ));
            }

            let nonce = &encrypted_data[60..72];
            let ciphertext = &encrypted_data[72..];

            let per_file_key = match STANDARD.decode(key) {
                Ok(key) => key,
                Err(e) => {
                    println!("❌ Base64 decode failed for key '{}': {}", key, e);
                    return Err(anyhow::anyhow!(
                        "Invalid per-file key (base64 decode failed): {}",
                        e
                    ));
                }
            };

            let cipher = match Aes256Gcm::new_from_slice(&per_file_key) {
                Ok(cipher) => cipher,
                Err(e) => {
                    println!("❌ Invalid key length for '{}': {}", key, e);
                    return Err(anyhow::anyhow!(
                        "Invalid per-file key length (expected 32 bytes): {}",
                        e
                    ));
                }
            };

            let plaintext = match cipher.decrypt(Nonce::from_slice(nonce), ciphertext) {
                Ok(data) => data,
                Err(e) => {
                    println!("❌ Decryption failed with key '{}': {}", key, e);
                    return Err(anyhow::anyhow!(
                        "Decryption failed with per-file key: {}",
                        e
                    ));
                }
            };

            // Mellomlagring i temp
            fs::write(&temp_file, &plaintext).await?;
            println!("📥 Temporary file stored at {}", temp_file.display());

            // Flytt til endelig plassering
            if let Some(parent) = final_output_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            fs::rename(&temp_file, &final_output_path).await?;
            println!(
                "✅ File downloaded and decrypted to {}",
                final_output_path.display()
            );
            plaintext
        } else {
            // Mellomlagring av kryptert fil
            fs::write(&temp_file, &encrypted_data).await?;
            println!("📥 Temporary file stored at {}", temp_file.display());

            if let Some(parent) = final_output_path.parent() {
                fs::create_dir_all(parent).await?;
            }
            let decrypted: DecryptedData<Vec<u8>> = timeout(
                Duration::from_secs(10),
                decrypt_file(&temp_file, Some(&final_output_path)),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Timeout waiting for master key decryption"))??;

            // Slett temp-fil etter dekryptering
            fs::remove_file(&temp_file).await?;
            println!("🗑️ Temporary file removed: {}", temp_file.display());

            match decrypted {
                DecryptedData::Raw(data) => {
                    println!(
                        "✅ File downloaded and decrypted with master key to {}",
                        final_output_path.display()
                    );
                    data
                }
                DecryptedData::Structured(_) => unreachable!("Expected raw bytes"),
            }
        }
    } else {
        // Mellomlagring av ukryptert fil
        fs::write(&temp_file, &encrypted_data).await?;
        println!("📥 Temporary file stored at {}", temp_file.display());

        // Flytt til endelig plassering
        if let Some(parent) = final_output_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::rename(&temp_file, &final_output_path).await?;
        println!("✅ File downloaded to {}", final_output_path.display());
        encrypted_data.to_vec()
    };

    Ok(data)
}