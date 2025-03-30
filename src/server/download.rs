use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::Client;
use crate::encryption::{decrypt_file, DecryptedData};
use std::path::PathBuf;
use tokio::fs;

pub struct Args {
    pub output: Option<PathBuf>,
    pub key: Option<String>,
    pub encrypted: bool,
    pub filename: String,
    pub filepath: String,
}

// Extracted download function
pub async fn download_file(client: &Client, cid: &str, args: &Args) -> Result<Vec<u8>> {
    let local_url = "http://localhost:5002/api/v0/cat".to_string();
    let response = client
        .post(&local_url)
        .query(&[("arg", cid)])
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to download file from local node: {}",
            response.status()
        ));
    }
    

    let data = response.bytes().await?.to_vec();
    let encrypted_data = data.clone();
    let filename = args.filename.clone();
    let filepath = args.filepath.clone();

    let full_path = PathBuf::from(&filepath).join(&filename);

    let output_path = args.output.as_ref().map(|p| p.clone()).unwrap_or_else(|| {
        let path = PathBuf::from(&full_path);
        path
    });

    if let Some(key) = &args.key {
        // Decrypt with per-file key
        if encrypted_data.len() < 72 {
            return Err(anyhow::anyhow!("Encrypted file too short."));
        }

        let nonce = &encrypted_data[60..72]; // 12 bytes
        let ciphertext = &encrypted_data[72..];

        let per_file_key = STANDARD
            .decode(key)
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
        let temp_file =
            std::env::temp_dir().join(format!("sdrive_download_{}.enc", rand::random::<u64>()));
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

    // Optionally save to output_path if provided
    if let Some(path) = &args.output {
        tokio::fs::write(path, &data).await?;
        println!("✅ File saved to {}", path.display());
    }

    Ok(data)
}
