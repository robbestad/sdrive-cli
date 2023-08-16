use indicatif::{ProgressBar, ProgressStyle};
use mime_guess::from_path;
use reqwest::{Client, StatusCode};
use std::fs;
use dirs::home_dir;
use std::env;
use dialoguer::Input;

use std::io::{self, Write};


use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use uuid::Uuid;

use reqwest::multipart::{Form, Part};


#[derive(Debug, Deserialize)]
struct Config {
    //owner: String,
    storage_account: String,
    userid: u32,
    username: String,
    encrypted: bool,
    //folder_id: u32,
    api_key: String,
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
        ])
        .multipart(form)
        .send()
        .await?;

    pb.inc(1);

    Ok(())
}

async fn is_valid_api_key(api_key: &str, username: &str) -> Result<bool, reqwest::Error> {
    let url = format!(
        "https://sdrive.app/api/v1/apikey/verify?key={}&username={}",
        api_key, username
    );
    let response = reqwest::get(&url).await?;
    let status = response.status();

    if status == reqwest::StatusCode::OK {
        Ok(true)
    } else {
        Ok(false)
    }
}




async fn upload_file(file_path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut config_path: PathBuf = match home_dir() {
        Some(path) => path,
        None => panic!("Failed to find the user's home directory."),
    };

    println!("sdriveupload v{}", env!("CARGO_PKG_VERSION"));

    config_path.push(".config");
    config_path.push("sdrive.toml");
    let config_str = fs::read_to_string(config_path).expect("Failed to read the configuration file.");
    let config: Config = toml::from_str(&config_str)?;

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

    let file_name = match file_path.file_name() {
        Some(name) => name.to_string_lossy().to_string(),
        None => panic!("Failed to get the file name."),
    };


    // Get file size.
    let file_size = file_path.metadata()?.len() as usize;

    // Get MIME type and extension.
    let mime_type = from_path(&file_path).first_or_octet_stream();
    let mime = mime_type.essence_str().to_string();
    let ext = file_path
        .extension()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    // Generate filename and GUID.
    let file_guid = format!("sdrive-{}", Uuid::new_v4());
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
        upload_chunk(&buffer, i, &file_name, &file_guid, &pb).await?;
    }
    pb.finish_with_message("Upload completed");

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
            "ext": ext,
            "folder_id": 0,
            "mode": "ctr"
        }))
        .send()
        .await?;

  if response.status() == StatusCode::ACCEPTED {
        print!("\rUpload completed!");
        io::stdout().flush()?;
    }
    if !config.encrypted {
        println!("\rhttps://download.sdrive.app/public/{}/{}",config.storage_account,file_guid);
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

    // Check if the path is a file or a directory
    if path.is_file() {
        upload_file(path).await?;
    } else if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry_path = entry?.path();
            if entry_path.is_file() {
                upload_file(entry_path).await?;
            }
        }
    } else {
        eprintln!("The specified path is neither a file nor a directory.");
    }

    Ok(())
}

