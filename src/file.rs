use anyhow::Result;
use ignore::gitignore::GitignoreBuilder;
use reqwest::Client;
use reqwest::StatusCode;
use serde_json::json;
use std::path::PathBuf;
use tokio::fs;
const MAX_RETRIES: usize = 3;

pub async fn check_file_exists(api_key: &str, user_guid: &str, file_hash: &str) -> Result<bool> {
    let client = Client::new();
    tracing::debug!("Sjekker fil med hash: {} for bruker: {}", file_hash, user_guid);
    let response_hash = client
        .post("https://backend.sdrive.app/get-hash")
        .header("Authorization", format!("Bearer {}", api_key))
        .json(&json!({
            "userGuid": user_guid,
            "hash": file_hash
        }))
        .send()
        .await?;

    // Anta at et 200-status svar betyr at filen finnes, mens 404 betyr at den ikke finnes.
    match response_hash.status() {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => {
            eprintln!("Uventet status fra file-exists-endpoint: {}", status);
            Ok(false)
        }
    }
}

pub async fn is_file_uploaded(
    api_key: &str,
    user_guid: &str,
    file_hash: &str,
) -> Result<bool, anyhow::Error> {
    for attempt in 1..=MAX_RETRIES {
        match check_file_exists(api_key, user_guid, file_hash).await {
            Ok(true) => return Ok(true),
            Ok(false) => return Ok(false),
            Err(e) => {
                eprintln!("Attempt {}: Error: {}", attempt, e);
                return Err(anyhow::anyhow!("Failed to check if file exists: {}", e));
            }
        }
    }

    Err(anyhow::anyhow!("Exhausted all retries in is_file_uploaded"))
}


pub async fn file_exists_head(user_guid: &str, file_name: &str) -> Result<bool> {
    let url = format!("https://cdn.sdrive.pro/{}/{}", user_guid, file_name);
    let client = reqwest::Client::new();
    let response = client.head(&url).send().await?;

    match response.status() {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => {
            eprintln!("Uventet statuskode: {}", status);
            Ok(false)
        }
    }
}

pub async fn fetch_guid_from_cid(
    client: &Client,
    guid: &str,
    apikey: &str,
) -> Result<serde_json::Value> {
    let api_url = "https://backend.sdrive.app/cid-to-guid";
    tracing::debug!("Sending POST request to: {}", api_url);

    let payload = json!({
        "cid": guid,
        "apikey": apikey
    });

    let response = client.post(api_url).json(&payload).send().await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch file metadata: {}",
            response.status()
        ));
    }

    let json: serde_json::Value = response.json().await?;
    Ok(json)
}

pub async fn is_ignored(sync_path: &PathBuf, file_path: &PathBuf) -> bool {
    let gitignore = {
        let mut gitignore_builder = GitignoreBuilder::new(&sync_path);
        let ignore_file = sync_path.join(".sdrive-ignore");

        if ignore_file.exists() {
            let contents = fs::read_to_string(&ignore_file).await.unwrap_or_default();
            for line in contents.lines() {
                if !line.trim().is_empty() && !line.starts_with('#') {
                    gitignore_builder
                        .add_line(None, line)
                        .expect("Failed to add ignore pattern");
                }
            }
        } else {
            gitignore_builder
                .add_line(None, ".DS_Store")
                .expect("Failed to add default ignore");
        }

        gitignore_builder
            .build()
            .expect("Failed to build gitignore")
    };
    gitignore
        .matched(&file_path, file_path.is_dir())
        .is_ignore()
}
