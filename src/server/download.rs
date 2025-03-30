use anyhow::Result;
use reqwest::Client;
use std::path::PathBuf;

// Extracted download function
pub async fn download_file(client: &Client, cid: &str, output_path: Option<PathBuf>) -> Result<Vec<u8>> {
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

    // Optionally save to output_path if provided
    if let Some(path) = output_path {
        tokio::fs::write(&path, &data).await?;
        println!("✅ File saved to {}", path.display());
    }

    Ok(data)
}
