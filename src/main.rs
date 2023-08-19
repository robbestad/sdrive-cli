use indicatif::{ProgressBar, ProgressStyle};
use std::borrow::Cow;
use std::path::Path;
use std::fmt;
use dialoguer::Input;
use dirs::home_dir;
use mime_guess::from_path;
use reqwest::{Client, StatusCode};
use std::env;
use std::fs;
use sha2::{Sha256, Digest};

use std::io::{self, Write};

use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use reqwest::multipart::{Form, Part};

const MAX_RETRIES: usize = 5;

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

#[derive(Debug)]
enum FileStatus {
    AlreadyUploaded,
    NotUploaded,
    Error(CustomError),
}

#[derive(Debug, Deserialize)]
struct Config {
    storage_account: String,
    userid: u32,
    encrypted: bool,
    username: String,
    api_key: String,
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

fn compute_hash<T: Hash>(t: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    t.hash(&mut hasher);
    hasher.finish()
}

async fn complete_upload(file_name: &str, chunk_count: usize) -> Result<(), reqwest::Error> {
    let client = Client::new();

    let response = client
        .post("https://upload.sdrive.app/complete_upload")
        .json(&json!({
            "fileName": file_name,
            "chunkCount": chunk_count,
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
    println!("hash {}", &file_hash);

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
                        "Attempt {}: Received unexpected status: {}. Response: {:?}",
                        attempt,
                        res.status(),
                        res.text().await.unwrap_or_default()
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

async fn is_valid_api_key(api_key: &str, username: &str) -> Result<bool, reqwest::Error> {
    let url = format!(
        "https://sdrive.app/api/v1/apikey/verify?key={}&username={}",
        api_key, username
    );

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

async fn upload_file(
    file_path: PathBuf,
    parent_folder: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    //println!("File path: {}", &file_path.display());
    //println!("Parent folder: {}", &parent_folder.display());

    let mut config_path: PathBuf = match home_dir() {
        Some(path) => path,
        None => panic!("Failed to find the user's home directory."),
    };
    let file_name = match file_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => panic!("Failed to get the file name."),
    };

    println!(
        "sdriveupload v{}. Uploading {}",
        env!("CARGO_PKG_VERSION"),
        &file_name
    );

    config_path.push(".config");
    config_path.push("sdrive.toml");
    let config_str =
        fs::read_to_string(config_path).expect("Failed to read the configuration file.");
    let config: Config = toml::from_str(&config_str)?;

    let mut folder = parent_folder.display().to_string();
    if !folder.starts_with("/") {
        folder.insert(0, '/');
    }

    let api_key = config.api_key;
    let username = config.username;
    let is_valid = is_valid_api_key(&api_key, &username).await?;

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
    println!("File status: {:?}", file_status);

    match file_status {
        FileStatus::AlreadyUploaded => {
            println!("\rThe file has already been uploaded.");
                        std::io::stdout().flush().unwrap();
            return Ok(());
            // Continue with next file
        }
        FileStatus::NotUploaded => {
            // Do the upload or whatever is needed
        }
        FileStatus::Error(e) => {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                        format!("Unexpected state in is_file_uploaded: {}", e),
            )));
        }
    }

    // Generate filename and GUID.
    let cloned_file_name = file_name.clone();
    let file_hash = compute_sha256_for_filename_and_size(&cloned_file_name, file_size);
    let file_guid = format!("sdrive-{}", file_hash);
    let chunk_size = 1048576 * 64; // 1000MB
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
    }
    pb.finish_with_message("Upload completed\n");

    complete_upload(&file_guid, chunk_count).await?;

    let response = client
        .post("https://upload.sdrive.app/processupload")
        .json(&json!({
            "fileName": file_name,
            "guid": file_guid,
            "fileSize": file_size,
            "fileIndex": 0,
            "count": chunk_count,
            "owner": "",
            "storageAccount": config.storage_account,
            "userid": config.userid,
            "encrypted": config.encrypted,
            "username": username,
            "mime": mime,
            "ext": &*ext,
            "folder": folder,
            "mode": "ctr"
        }))
        .send()
        .await?;

    if response.status() == StatusCode::ACCEPTED {
        println!("Upload completed!");
        io::stdout().flush()?;
    }

    let response_hash = client
        .post("https://sdrive.app/api/v3/set-hash")
        .json(&json!({
            "key": api_key,
            "file_hash": file_hash
        }))
        .send()
        .await?;

    if response.status() == StatusCode::ACCEPTED {
        println!("Hash set!");
        io::stdout().flush()?;
    }

    if !config.encrypted {
        println!(
            "\rhttps://download.sdrive.app/public/{}/{}",
            config.storage_account, file_guid
        );
    }
    Ok(())
}

#[async_recursion::async_recursion]
async fn handle_directory(dir_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir_path)? {
        let entry_path = entry?.path();
        if entry_path.is_file() {
            let parent_folder = entry_path.parent().unwrap_or(&entry_path);
            println!(
                "Parent folder of {}: {}",
                &entry_path.display(),
                parent_folder.display()
            );
            upload_file(entry_path.clone(), parent_folder.to_path_buf()).await?;
        } else if entry_path.is_dir() {
            handle_directory(&entry_path).await?; // Recursive call
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let path: PathBuf = if args.len() < 2 {
        Input::<String>::new()
            .with_prompt("Enter file or directory path")
            .interact_text()?
            .into()
    } else {
        args[1].clone().into()
    };

    if path.is_file() {
        let parent_folder = path.parent().unwrap_or(&path).to_path_buf();
        println!("Parent folder: {}", &parent_folder.display());
        upload_file(path.clone(), parent_folder).await?;
    } else if path.is_dir() {
        handle_directory(&path).await?;
    } else {
        eprintln!("The specified path is neither a file nor a directory.");
    }

    Ok(())
}
