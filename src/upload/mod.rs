use crate::encryption::encrypt_file;
use crate::secret::get_value_from_env_or_config;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use indicatif::{ProgressBar, ProgressStyle};
use mime_guess::from_path;
use reqwest::multipart::{Form, Part};
use reqwest::Client;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::path::PathBuf;
use tokio::time::sleep;
use tokio::time::Duration;
mod poll;
use poll::poll_file_status;

const MAX_RETRIES: usize = 3;

#[derive(Debug)]
enum CustomError {
    ReqwestError(reqwest::Error),
    IoError(std::io::Error),
}
impl fmt::Display for CustomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomError::ReqwestError(e) => write!(f, "Reqwest Error: {}", e),
            CustomError::IoError(e) => write!(f, "IO Error: {}", e),
        }
    }
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn compute_sha256_for_filename_size_and_content(file_path: &str) -> io::Result<String> {
    // Open the file
    let mut file = File::open(file_path)?;

    // Get file size
    let file_size = file.metadata()?.len() as usize;

    // Create initial data with filename
    let mut data = file_path.as_bytes().to_vec();

    // Add file size
    let size_bytes = file_size.to_le_bytes();
    data.extend(&size_bytes);

    // Read first 1024 bytes (or less if file is smaller)
    let mut buffer = vec![0u8; 1024.min(file_size)];
    let bytes_read = file.read(&mut buffer)?;
    data.extend_from_slice(&buffer[..bytes_read]);

    // Compute and return SHA256
    Ok(compute_sha256(&data))
}

#[derive(Debug, Serialize)]
struct ChunkInfo {
    #[serde(rename = "chunkIndex")]
    chunk_index: usize,
    file_name: String,
    #[serde(rename = "fileId")]
    file_id: String,
}

#[derive(Debug)]
enum FileStatus {
    AlreadyUploaded,
    NotUploaded,
    Error(CustomError),
}

async fn complete_upload(
    file_name: &str,
    chunk_count: usize,
    chunks: &[ChunkInfo],
    api_key: &str,
    _nonce_b64: &str, // inkluder nonce som base64
) -> Result<(), reqwest::Error> {
    let client = Client::new();

    let response = client
        .post("https://upload.sdrive.app/reassemble_upload")
        .header("Content-Type", "application/json")
        .json(&json!({
            "fileName": file_name,
            "chunkCount": chunk_count,
            "chunks": chunks,
            "apikey": api_key,
        }))
        .send()
        .await?;

    if response.status().as_u16() == 201 {
        // Chunks reassembled successfully
    } else {
        println!("Error reassembling chunks: {}", response.status());
    }

    Ok(())
}

async fn upload_chunk(
    chunk: &[u8],
    i: usize,
    file_name: &str,
    file_guid: &str,
    api_key: &str,
    pb: &ProgressBar,
) -> Result<(), reqwest::Error> {
    let client = Client::new();
    let file_part = Part::stream(chunk.to_owned())
        .file_name(file_name.to_string())
        .mime_str("application/octet-stream")?;

    let form = Form::new().part("file", file_part);

    let _response = client
        .post("https://upload.sdrive.app/upload_data_chunks")
        .query(&[
            ("id", i.to_string()),
            ("fileName", file_name.to_string()),
            ("identifier", file_guid.to_string()),
            ("apikey", api_key.to_string()),
        ])
        .multipart(form)
        .send()
        .await?;

    pb.inc(1);
    Ok(())
}

async fn is_file_uploaded(
    api_key: &str,
    _file_name: &str,
    _file_size: &usize,
    file_hash: &str,
) -> FileStatus {
    let url = format!(
        "https://sdrive.app/api/v3/file-exists?key={}&file_hash={}",
        api_key, file_hash
    );

    for attempt in 1..=MAX_RETRIES {
        let response = reqwest::get(&url).await;
        match response {
            Ok(res) => match res.status() {
                reqwest::StatusCode::OK => return FileStatus::AlreadyUploaded,
                reqwest::StatusCode::NOT_FOUND => return FileStatus::NotUploaded,
                _ => {
                    eprintln!(
                        "Attempt {}: Received unexpected status: {}",
                        attempt,
                        res.status()
                    );
                }
            },
            Err(e) => {
                eprintln!("Attempt {}: Error: {}", attempt, e);
                return FileStatus::Error(CustomError::ReqwestError(e));
            }
        }
        if attempt < MAX_RETRIES {
            sleep(Duration::from_secs(1)).await;
        }
    }
    eprintln!("Unexpected state reached in is_file_uploaded");
    FileStatus::Error(CustomError::IoError(io::Error::new(
        io::ErrorKind::Other,
        "Unexpected state in is_file_uploaded",
    )))
}

async fn is_valid_api_key(api_key: &str) -> Result<bool, reqwest::Error> {
    let url = format!(
        "https://api.sdrive.app/api/v1/apikey/verify?key={}",
        api_key
    );
    tracing::debug!("Verifying API key: {}", url);
    for attempt in 1..=MAX_RETRIES {
        let response = reqwest::get(&url).await;
        match response {
            Ok(res) => {
                if res.status() == reqwest::StatusCode::OK {
                    return Ok(true);
                } else {
                    eprintln!(
                        "Attempt {}: Received unexpected status: {}. Response: {:?}",
                        attempt,
                        res.status(),
                        res.text().await.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                eprintln!("Attempt {}: Error: {}", attempt, e);
            }
        }
        if attempt < MAX_RETRIES {
            sleep(Duration::from_secs(1)).await;
        }
    }
    Ok(false)
}

pub async fn process_upload(
    path: PathBuf,
    parent_folder: PathBuf,
    config_path: String,
    unencrypted: bool,
    overwrite: bool,
) -> Result<()> {
    if path.is_file() {
        upload_file(path, parent_folder, unencrypted, overwrite).await?;
    } else if path.is_dir() {
        handle_directory(&path, &config_path, unencrypted, overwrite).await?;
    } else {
        eprintln!("The specified path is neither a file nor a directory.");
    }
    Ok(())
}

pub async fn upload_file(
    file_path: PathBuf,
    parent_folder: PathBuf,
    unencrypted: bool,
    overwrite: bool,
) -> Result<()> {
    let file_name = match file_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => panic!("Failed to get the file name."),
    };

    // Skip .DS_Store files
    if file_name == ".DS_Store" {
        println!("⏭️ Skipping .DS_Store file");
        return Ok(());
    }

    println!("🚀 Uploading {}", &file_name);

    let mut folder = parent_folder.display().to_string();
    if !folder.starts_with("/") {
        folder.insert(0, '/');
    }

    // 🔑 Hent API-nøkkel
    let api_key = get_value_from_env_or_config("SDRIVE_API_KEY", "api_key", Some("sdrive")).await?;

    // 🆔 Hent bruker-GUID
    let user_guid =
        get_value_from_env_or_config("SDRIVE_USER_GUID", "user_guid", Some("sdrive")).await?;

    let is_valid = is_valid_api_key(&api_key).await?;
    if !is_valid {
        println!("\rThe API key is invalid.");
        return Err(anyhow::anyhow!("Invalid API key"));
    }

    if user_guid.is_empty() {
        return Err(anyhow::anyhow!("User GUID er ikke satt i config"));
    }
    println!("✅ API Key and User GUID validated.");

    // // Sjekk om filen allerede finnes
    let overwrite_file: bool = overwrite;

    // Hvis --unencrypted er satt, hopp over kryptering
    let (file_content, nonce_b64, _per_file_key_option) = if unencrypted {
        let content = std::fs::read(&file_path)?;
        (content, "".to_string(), None)
    } else {
        let (encrypted_content, per_file_key) = encrypt_file(&file_path).await?;
        let encrypted_file_size = encrypted_content.len();
        if encrypted_file_size < 56 {
            return Err(anyhow::anyhow!(
                "Encrypted data too short to contain key and nonce: {} bytes",
                encrypted_file_size
            ));
        }
        // Ekstraher nonce (merk at dette avhenger av hvordan `encrypt_file` pakker data)
        let (_encrypted_key, rest) = encrypted_content.split_at(32);
        let (_key_nonce, rest) = rest.split_at(12);
        let (nonce, _ciphertext) = rest.split_at(12);
        let nonce_b64: String = STANDARD.encode(nonce);
        println!("🔑 To share this file securely, use this file key");
        println!("🔑 {}", STANDARD.encode(per_file_key));
        (encrypted_content, nonce_b64, Some(per_file_key))
    };

    let file_size = file_content.len();
    let file_hash = compute_sha256_for_filename_size_and_content(file_path.to_str().unwrap())?;

    let file_status = is_file_uploaded(&api_key, &file_name, &file_size, &file_hash).await;
    match file_status {
        FileStatus::AlreadyUploaded => {
            println!(
                "\rYou have recently uploaded this file. Likely url: https://cdn.sdrive.pro/{}/{}",
                user_guid, file_name
            );
            std::io::stdout().flush()?;
            return Ok(());
        }
        FileStatus::NotUploaded => {
            let file_guid = &file_hash[0..24].to_string();
            let chunk_size = 1048576; // 1MB
            let mut chunk_count = file_size / chunk_size + 1;
            if file_size % chunk_size == 0 {
                chunk_count -= 1;
            }
            let client = reqwest::Client::new();
            let pb = ProgressBar::new(chunk_count as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})")?
                    .progress_chars("##-"),
            );
            let mut chunks = Vec::new();
            for i in 0..chunk_count {
                let start = i * chunk_size;
                let end = std::cmp::min(start + chunk_size, file_size);
                let chunk = &file_content[start..end];
                upload_chunk(chunk, i, &file_name, &file_guid, &api_key, &pb).await?;
                chunks.push(ChunkInfo {
                    chunk_index: i,
                    file_name: file_name.clone(),
                    file_id: file_guid.clone(),
                });
            }
            pb.finish_with_message("Upload completed\n");

            // Fullfør opplastingen – i unencrypted modus kan nonce være en tom streng
            complete_upload(&file_guid, chunk_count, &chunks, &api_key, &nonce_b64).await?;
            tracing::debug!("Upload completed");
            tracing::debug!("API key: {}", api_key);
            tracing::debug!("User GUID: {}", user_guid);
            tracing::debug!("File name: {}", file_name);
            tracing::debug!("File size: {}", file_size);
            tracing::debug!("File hash: {}", file_hash);
            tracing::debug!("Overwrite file: {}", overwrite_file);
            // Endelig POST-request for å signalisere ferdig opplasting
            let response = client
                .post("https://upload.sdrive.app/processupload")
                .header("Content-Type", "application/json")
                .json(&json!({
                    "fileName": file_name,
                    "guid": file_guid,
                    "fileSize": file_size,
                    "fileIndex": 0,
                    "count": chunk_count,
                    "owner": "",
                    "userid": 0,
                    "overwrite": overwrite_file,
                    "storageAccount": "none",
                    "encrypted": !unencrypted, // setter false om --unencrypted er satt
                    "nonce": nonce_b64,
                    "transcode": false,
                    "username": "anon",
                    "mime": from_path(&file_path).first_or_octet_stream().essence_str().to_string(),
                    "ext": file_path.extension().map_or("".to_string(), |e| e.to_string_lossy().to_string()),
                    "folder": "/",
                    "mode": "ctr",
                    "storageNetwork": "ipfs",
                    "apikey": api_key,
                    "user_guid": user_guid,
                }))
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::ACCEPTED {
                std::io::stdout().flush()?;
            } else {
                println!("Upload failed…");
                std::io::stdout().flush()?;
                return Ok(());
            }
            let _response_hash = client
                .post("https://upload.sdrive.app/api/v3/set-hash")
                .json(&json!({
                    "key": api_key,
                    "file_hash": file_hash
                }))
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::ACCEPTED {
                std::io::stdout().flush()?;
            }
            let _response_uploaded = client
                .post("https://upload.sdrive.app/api/v1/files")
                .json(&json!({
                    "filename": file_name,
                    "guid": file_guid,
                    "username": "anon"
                }))
                .send()
                .await?;
            if response.status() == reqwest::StatusCode::ACCEPTED {
                println!("✅ Upload success. Finalizing URL...");
                std::io::stdout().flush()?;
            }
            match poll_file_status(&client, &file_guid).await {
                Ok(url) => println!("🔗 Your file is available at: {}", url),
                Err(e) => println!("Error: {}", e),
            }
        }
        FileStatus::Error(e) => {
            return Err(anyhow::anyhow!(
                "Unexpected state in is_file_uploaded: {}",
                e
            ));
        }
    }
    Ok(())
}

pub async fn pin_file(file_path: PathBuf, unencrypted: bool) -> Result<(String, String)> {
    let client = Client::new();
    let ipfs_api_url = "http://localhost:5002/api/v0/add"; // 📌 Bruker lokal IPFS instans

    let file_name = file_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .context("❌ Kunne ikke hente filnavn")?;

    let mut file_key = "".to_string();
    println!("📌 Pinning lokalt i IPFS: {}", &file_name);

    // Sjekk om filen eksisterer før vi prøver å lese den
    if !file_path.exists() {
        return Err(anyhow::anyhow!("❌ Filen finnes ikke: {:?}", file_path));
    }
    println!("📂 Filstørrelse: {} bytes", file_path.metadata()?.len());

    // 🛡️ Krypter filen hvis ikke --unencrypted er satt
    let (file_content, _nonce_b64, per_file_key_option) = if unencrypted {
        let content = tokio::fs::read(&file_path)
            .await
            .with_context(|| format!("❌ Kunne ikke lese filen: {:?}", file_path))?;
        println!("✅ Fil lest (ukryptert): {} bytes", content.len());
        (content, "".to_string(), None)
    } else {
        println!("🔐 Starter kryptering av fil...");
        let (encrypted_content, per_file_key) = encrypt_file(&file_path).await?;
        println!("✅ Fil kryptert: {} bytes", encrypted_content.len());

        let encrypted_file_size = encrypted_content.len();
        if encrypted_file_size < 56 {
            return Err(anyhow::anyhow!(
                "🔐 Kryptert data er for kort: {} bytes (minimum 56 bytes kreves)",
                encrypted_file_size
            ));
        }
        let (_encrypted_key, rest) = encrypted_content.split_at(32);
        let (_key_nonce, rest) = rest.split_at(12);
        let (nonce, _ciphertext) = rest.split_at(12);
        let nonce_b64 = STANDARD.encode(nonce);
        file_key = STANDARD.encode(&per_file_key);
        println!(
            "🔑 Del denne filen sikkert med denne nøkkelen: {}",
            file_key
        );
        (encrypted_content, nonce_b64, Some(per_file_key))
    };

    // 📡 Last opp til IPFS (lokalt)
    println!("📤 Starter opplasting til IPFS...");
    let form = reqwest::multipart::Form::new().part(
        "file",
        reqwest::multipart::Part::bytes(file_content.clone()),
    );

    let response = client
        .post(ipfs_api_url)
        .multipart(form)
        .send()
        .await
        .with_context(|| "❌ Feil ved opplasting til lokal IPFS")?;

    println!("🔍 HTTP Status: {}", response.status());

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "⚠️ Kunne ikke lese feilmelding".to_string());
        return Err(anyhow::anyhow!(
            "❌ IPFS opplasting feilet med status {}: {}",
            status,
            error_text
        ));
    }

    let response_text = response
        .text()
        .await
        .unwrap_or_else(|_| "⚠️ Mottok ingen respons".to_string());
    println!("📥 Mottok respons fra IPFS: {}", response_text);

    // 📍 Hent CID fra svaret
    let cid: serde_json::Value = serde_json::from_str(&response_text)
        .with_context(|| format!("❌ Kunne ikke parse IPFS respons: {}", response_text))?;

    let hash = cid["Hash"]
        .as_str()
        .context("❌ CID mangler i responsen")?
        .to_string();

    println!("✅ Fil pinned i lokal IPFS-node! CID: {}", hash);

    // 📌 Pin CID lokalt
    println!("📌 Pinner CID lokalt...");
    let pin_url = format!("http://localhost:5002/api/v0/pin/add?arg={}", hash);
    let pin_response = client
        .post(&pin_url)
        .send()
        .await
        .with_context(|| "❌ Feil ved pinning av CID")?;

    println!("🔍 HTTP Status (pinning): {}", pin_response.status());

    if pin_response.status().is_success() {
        let parent_folder = file_path.parent().unwrap_or(&file_path).to_path_buf();
        let overwrite = true;
        let unencrypted = true;
        println!("💾 Uploading file to SDrive...");
        //upload_file(file_path, parent_folder, unencrypted, overwrite).await?;
    }

    if !pin_response.status().is_success() {
        let status = pin_response.status();
        let error_text = pin_response
            .text()
            .await
            .unwrap_or_else(|_| "⚠️ Kunne ikke lese feilmelding".to_string());
        return Err(anyhow::anyhow!(
            "❌ Pinning feilet med status {}: {}",
            status,
            error_text
        ));
    }

    println!("✅ CID {} er nå pinned lokalt!", hash);
    Ok((hash, file_key))
}

#[async_recursion::async_recursion]
pub async fn handle_directory(
    dir_path: &Path,
    config_path: &String,
    unencrypted: bool,
    overwrite: bool,
) -> Result<()> {
    for entry in std::fs::read_dir(dir_path)? {
        let entry_path = entry?.path();
        if entry_path.is_file() {
            let parent_folder = entry_path.parent().unwrap_or(&entry_path);
            upload_file(
                entry_path.clone(),
                parent_folder.to_path_buf(),
                unencrypted,
                overwrite,
            )
            .await?;
        } else if entry_path.is_dir() {
            handle_directory(&entry_path, config_path, unencrypted, overwrite).await?;
        }
    }
    Ok(())
}
