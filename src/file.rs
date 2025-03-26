use reqwest::StatusCode;
use anyhow::Result;

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