use reqwest::StatusCode;
use anyhow::Result;
use reqwest::Client;
use serde_json::json;

pub async fn check_file_exists(user_guid: &str, file_name: &str) -> Result<bool> {
    let url = format!(
        "https://backend.sdrive.app/file-exists?userGuid={}&filename={}",
        user_guid, file_name
    );
    println!("Checking if file exists: {}", url);
    let response = reqwest::get(&url).await?;
    
    // Anta at et 200-status svar betyr at filen finnes, mens 404 betyr at den ikke finnes.
    match response.status() {
        StatusCode::OK => Ok(true),
        StatusCode::NOT_FOUND => Ok(false),
        status => {
            eprintln!("Uventet status fra file-exists-endpoint: {}", status);
            Ok(false)
        }
    }
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

pub async fn fetch_guid_from_cid(client: &Client, guid: &str, apikey: &str) -> Result<serde_json::Value> {
    let api_url = "https://backend.sdrive.app/cid-to-guid";
    tracing::debug!("Sending POST request to: {}", api_url);

    let payload = json!({
        "cid": guid,
        "apikey": apikey
    });

    let response = client
        .post(api_url)
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch file metadata: {}",
            response.status()
        ));
    }

    let json: serde_json::Value = response.json().await?;
    Ok(json)
}