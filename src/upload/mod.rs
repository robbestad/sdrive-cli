use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use indicatif::{ProgressBar, ProgressStyle};
use mime_guess::from_path;
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::cmp::min;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use tokio::time::sleep;
use tokio::time::Duration;

use crate::config::read_config;
use crate::encryption::encrypt_file; // Importer krypteringsfunksjonen
use base64::Engine;
use reqwest::multipart::{Form, Part};
use serde::Serialize;
use serde_json::json;
use std::path::PathBuf;
mod poll; // Deklarerer poll som en modul i samme katalog
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
fn compute_sha256_for_filename_and_size(file_name: &str, file_size: usize) -> String {
    let mut data = file_name.as_bytes().to_vec();
    let size_bytes = file_size.to_le_bytes();
    data.extend(&size_bytes);
    compute_sha256(&data)
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
    nonce_b64: &str, // inkluder nonce som base64
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
            "nonce": nonce_b64,  // Send med nonce
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

async fn is_file_uploaded(api_key: &str, file_name: &str, file_size: &usize) -> FileStatus {
    let file_hash = compute_sha256_for_filename_and_size(file_name, *file_size);
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
) -> Result<()> {
    if path.is_file() {
        upload_file(path, parent_folder, config_path).await?;
    } else if path.is_dir() {
        handle_directory(&path, &config_path).await?;
    } else {
        eprintln!("The specified path is neither a file nor a directory.");
    }
    Ok(())
}

pub async fn upload_file(
    file_path: PathBuf,
    parent_folder: PathBuf,
    config_path: String,
) -> Result<()> {
    let config = read_config(Some(config_path)).await?;
    let file_name = match file_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => panic!("Failed to get the file name."),
    };
    println!("🚀 Uploading {}", &file_name);
    let mut folder = parent_folder.display().to_string();
    if !folder.starts_with("/") {
        folder.insert(0, '/');
    }
    let api_key = config.api_key.as_deref().unwrap_or("");
    let user_guid = config.user_guid.as_deref().unwrap_or("");
    let is_valid = is_valid_api_key(&api_key).await?;
    if !is_valid {
        println!("\rThe API key is invalid.");
        return Err(anyhow::anyhow!("Invalid API key"));
    }
    let (encrypted_content, per_file_key) = encrypt_file(&file_path)?;
    //fs::write("test_encrypted.enc", &encrypted_content)?; // Debugging
    //tracing::debug!("Saved encrypted file to test_encrypted.enc for debugging, size: {} bytes", encrypted_content.len());
    let encrypted_file_size = encrypted_content.len();
    if encrypted_file_size < 56 {
        return Err(anyhow::anyhow!(
            "Encrypted data too short to contain key and nonce: {} bytes",
            encrypted_file_size
        ));
    }
    let (_encrypted_key, rest) = encrypted_content.split_at(32);
    let (_key_nonce, rest) = rest.split_at(12);
    let (nonce, _ciphertext) = rest.split_at(12);
    let nonce_b64 = STANDARD.encode(nonce);
    //tracing::info!("🔑 To share this file securely, use this file key: {}", STANDARD.encode(per_file_key));
    println!("🔑 To share this file securely, use this file key");
    println!("🔑 {}", STANDARD.encode(per_file_key));
    tracing::debug!("Nonce (base64): {}", nonce_b64);

    let mime_type = from_path(&file_path).first_or_octet_stream();
    let mime = mime_type.essence_str().to_string();
    let ext: Cow<str> = file_path
        .extension()
        .map_or(Cow::Borrowed(""), |e| e.to_string_lossy());
    let file_status = is_file_uploaded(&api_key, &file_name, &encrypted_file_size).await;
    match file_status {
        FileStatus::AlreadyUploaded => {
            println!(
                "\rYou have recently uploaded this file. Likely url: https://cdn.sdrive.pro/{}/{}",
                &user_guid, &file_name
            );
            io::stdout().flush()?;
            return Ok(());
        }
        FileStatus::NotUploaded => {
            let file_hash = compute_sha256_for_filename_and_size(&file_name, encrypted_file_size);
            let file_guid = &file_hash[0..24].to_string();
            let chunk_size = 1048576; // 1MB
            let mut chunk_count = encrypted_file_size / chunk_size + 1;
            if encrypted_file_size % chunk_size == 0 {
                chunk_count -= 1;
            }
            let client = Client::new();
            let pb = ProgressBar::new(chunk_count as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})")?
                    .progress_chars("##-"),
            );
            let mut chunks = Vec::new();
            for i in 0..chunk_count {
                let start = i * chunk_size;
                let end = min(start + chunk_size, encrypted_file_size);
                let chunk = &encrypted_content[start..end];
                upload_chunk(chunk, i, &file_name, &file_guid, &api_key, &pb).await?;
                chunks.push(ChunkInfo {
                    chunk_index: i,
                    file_name: file_name.clone(),
                    file_id: file_guid.clone(),
                });
            }
            pb.finish_with_message("Upload completed\n");
            complete_upload(&file_guid, chunk_count, &chunks, &api_key, &nonce_b64).await?;
            let response = client
                .post("https://upload.sdrive.app/processupload")
                .header("Content-Type", "application/json")
                .json(&json!({
                    "fileName": file_name,
                    "guid": file_guid,
                    "fileSize": encrypted_file_size,
                    "fileIndex": 0,
                    "count": chunk_count,
                    "owner": "",
                    "userid": 0,
                    "storageAccount": "none",
                    "encrypted": true,
                    "nonce": nonce_b64,
                    "transcode": false,
                    "username": "anon",
                    "mime": mime,
                    "ext": &*ext,
                    "folder": "/",
                    "user_guid": user_guid,
                    "mode": "ctr",
                    "storageNetwork": "ipfs",
                    "apikey": api_key,
                }))
                .send()
                .await?;
            if response.status() == StatusCode::ACCEPTED {
                io::stdout().flush()?;
            } else {
                println!("Upload failed…");
                io::stdout().flush()?;
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
            if response.status() == StatusCode::ACCEPTED {
                io::stdout().flush()?;
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
            if response.status() == StatusCode::ACCEPTED {
                println!("✅ Upload success. Finalizing URL...");
                io::stdout().flush()?;
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

#[async_recursion::async_recursion]
pub async fn handle_directory(dir_path: &Path, config_path: &String) -> Result<()> {
    // Endret til anyhow::Result
    for entry in std::fs::read_dir(dir_path)? {
        let entry_path = entry?.path();
        if entry_path.is_file() {
            let parent_folder = entry_path.parent().unwrap_or(&entry_path);
            upload_file(
                entry_path.clone(),
                parent_folder.to_path_buf(),
                config_path.to_string(),
            )
            .await?;
        } else if entry_path.is_dir() {
            handle_directory(&entry_path, config_path).await?;
        }
    }
    Ok(())
}
