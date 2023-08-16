use indicatif::{ProgressBar, ProgressStyle};
use mime_guess::from_path;
use reqwest::{Client, StatusCode};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use tokio::time::sleep;
use tokio::time::Duration;

use crate::config::read_config;

use reqwest::multipart::{Form, Part};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

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
            // ... handle other variants as needed
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ResponseType {
    url: Option<String>,
    cdn_url: Option<String>,
    guid: String,
    filename: String,
}

fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    format!("{:x}", result)
}
fn compute_sha256_for_filename_and_size(file_name: &str, file_size: usize) -> String {
    let mut data = file_name.as_bytes().to_vec();
    let size_bytes = file_size.to_le_bytes(); // Convert the usize to its little-endian byte representation
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
) -> Result<(), reqwest::Error> {
    let client = Client::new();

    //println!("chunks being sent: {}", serde_json::to_string(&chunks).unwrap());
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
        //println!("Chunks reassembled successfully");
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
    //println!("Sending {:?}", &file_name);

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
    let file_hash = compute_sha256_for_filename_and_size(&file_name, *file_size);
    //println!("hash {}", &file_hash);

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

        // If not the last attempt, sleep before retrying.
        if attempt < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }
    eprintln!("Unexpected state reached in is_file_uploaded");
    FileStatus::Error(CustomError::IoError(std::io::Error::new(
        std::io::ErrorKind::Other,
        "Unexpected state in is_file_uploaded",
    )))
}

async fn is_valid_api_key(api_key: &str) -> Result<bool, reqwest::Error> {
    let url = format!("https://sdrive.app/api/v1/apikey/verify?key={}", api_key);

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

        // If not the last attempt, sleep before retrying.
        if attempt < MAX_RETRIES {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    }

    Ok(false)
}

pub async fn process_upload(
    path: PathBuf,
    parent_folder: PathBuf,
    config_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.is_file() {
        // Since parent_folder is already passed, you might not need to determine it again
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
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("File path: {}", &file_path.display());
    //println!("Parent folder: {}", &parent_folder.display());

    let config = read_config(Some(config_path)).await?;

    let file_name = match file_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => panic!("Failed to get the file name."),
    };

    println!("Uploading {}", &file_name);

    let mut folder = parent_folder.display().to_string();
    if !folder.starts_with("/") {
        folder.insert(0, '/');
    }

    let api_key = config.api_key.as_deref().unwrap_or("");
    let user_guid = config.user_guid.as_deref().unwrap_or("");
    let is_valid = is_valid_api_key(&api_key).await?;

    if !is_valid {
        println!("\rThe API key is invalid.");
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Invalid API key",
        )));
    }

    // Get file size.
    let file_size = file_path.metadata()?.len() as usize;

    // Get MIME type and extension.
    let mime_type = from_path(&file_path).first_or_octet_stream();
    let mime = mime_type.essence_str().to_string();
    let ext: Cow<str> = file_path
        .extension()
        .map_or(Cow::Borrowed(""), |e| e.to_string_lossy());

    let file_status = is_file_uploaded(&api_key, &file_name, &file_size).await;
    //println!("File status: {:?}", file_status);
    match file_status {
        FileStatus::AlreadyUploaded => {
            println!(
                "\rYou have recently uploaded this file. Likely url: https://cdn.sdrive.pro/{}/{}",
                &user_guid, &file_name
            );
            std::io::stdout().flush().unwrap();
            return Ok(());
            // Continue with next file
        }
        FileStatus::NotUploaded => {
            // Generate filename and GUID.
            let cloned_file_name = file_name.clone();
            let file_hash = compute_sha256_for_filename_and_size(&cloned_file_name, file_size);
            let file_guid = format!("sdrive-{}", file_hash);
            let chunk_size = 1048576 * 1; // 1MB
            let mut chunk_count = file_size / chunk_size + 1;

            if file_size % chunk_size == 0 {
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
                let mut file = File::open(&file_path)?;
                let beginning_of_chunk = i * chunk_size;
                file.seek(SeekFrom::Start(beginning_of_chunk as u64))?;
                // Calculate the size of the chunk
                let remaining_bytes = file_size - beginning_of_chunk;
                let this_chunk_size = if remaining_bytes > chunk_size {
                    chunk_size
                } else {
                    remaining_bytes
                };

                // Allocate a buffer of the appropriate size
                let mut buffer = vec![0; this_chunk_size as usize];

                // Read the chunk into the buffer
                file.read_exact(&mut buffer)?;
                upload_chunk(&buffer, i, &file_name, &file_guid, &api_key, &pb).await?;
                chunks.push(ChunkInfo {
                    chunk_index: i,
                    file_name: file_name.to_string(),
                    file_id: file_guid.to_string(),
                });
            }
            pb.finish_with_message("Upload completed\n");

            complete_upload(&file_guid, chunk_count, &chunks, &api_key).await?;

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
                    "owner": "",
                    "storageAccount": "none",
                    "encrypted": false,
                    "transcode": false,
                    "username": "anon",
                    "mime": mime,
                    "ext": &*ext,
                    "folder": "/",
                    "mode": "ctr",
                    "storageNetwork": "arweave",
                    "apikey": api_key,
                }))
                .send()
                .await?;

            if response.status() == StatusCode::ACCEPTED {
                //println!("Upload completed!");
                io::stdout().flush()?;
            } else {
                println!("Upload failed… You might be out of credits.");
                io::stdout().flush()?;
                return Ok(());
            }

            let _response_hash = client
                .post("https://sdrive.app/api/v3/set-hash")
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
                .post("https://sdrive.app/api/v1/files")
                .json(&json!({
                    "filename": file_name,
                    "guid": file_guid,
                    "username": "anon"
                }))
                .send()
                .await?;

            if response.status() == StatusCode::ACCEPTED {
                println!("Upload success. Finalizing URL...");
                io::stdout().flush()?;
            }

            let mut is_finished = false;
            let mut wait_seconds = 0;
            while !is_finished {
                // Correctly format the URL with the file GUID
                let url = format!("https://sdrive.app/api/v1/files?guid={}", file_guid);
                let response = client.get(&url).send().await?;
                let status = response.status();
                let body_text = response.text().await?;
                //println!("file_guid: {}", file_guid);
                //println!("HTTP Status: {}", status);
                //println!("Response Body: {}", body_text);

                if status.is_success() {
                    if let Ok(body) = serde_json::from_str::<ResponseType>(&body_text) {
                        if let Some(cdn_url) = body.cdn_url {
                            if !cdn_url.is_empty() {
                                println!("{}", cdn_url);
                                io::stdout().flush()?;
                                is_finished = true;
                            } else {
                                wait_seconds += 1;
                                sleep(Duration::from_secs(wait_seconds)).await;
                            }
                        } else if let Some(url) = body.url {
                            println!("{}", url);
                            io::stdout().flush()?;
                            is_finished = true;
                        } else {
                            wait_seconds += 1;
                            //println!("URL not found, retrying in {} second...",{wait_seconds});
                            sleep(Duration::from_secs(wait_seconds)).await;
                        }
                    } else {
                        println!("Failed to deserialize response.");
                        is_finished = true;
                    }
                } else {
                    println!("Non-success response, stopping.");
                    is_finished = true;
                }
            }
        }
        FileStatus::Error(e) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Unexpected state in is_file_uploaded: {}", e),
            )));
        }
    }

    Ok(())
}

#[async_recursion::async_recursion]
pub async fn handle_directory(
    dir_path: &Path,
    config_path: &String,
) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir_path)? {
        let entry_path = entry?.path();
        if entry_path.is_file() {
            let parent_folder = entry_path.parent().unwrap_or(&entry_path);
            /*println!(
                "Parent folder of {}: {}",
                &entry_path.display(),
                parent_folder.display()
            );*/
            upload_file(
                entry_path.clone(),
                parent_folder.to_path_buf(),
                config_path.to_string(),
            )
            .await?;
        } else if entry_path.is_dir() {
            handle_directory(&entry_path, &config_path).await?; // Recursive call
        }
    }
    Ok(())
}
