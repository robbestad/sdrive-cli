use reqwest::Client;
use serde::Deserialize;
use std::io;
use std::io::Write;
use std::time::Duration;
use tokio::time::sleep;

#[derive(Deserialize, Debug)]
pub struct ResponseType {
    cdn_url: Option<String>,
    url: Option<String>,
}

pub async fn poll_file_status(client: &Client, file_guid: &str) -> Result<String, anyhow::Error> {
    let is_finished = false;
    let mut wait_seconds = 0;
    let max_attempts = 10;

    tracing::debug!("File GUID: {}", file_guid); // Debug the GUID

    while !is_finished && wait_seconds < max_attempts {
        let url = format!("https://api.sdrive.app/api/v1/files?guid={}", file_guid);
        tracing::debug!("Polling URL: {}", url); // Debug the polling URL

        let response = client
            .get(&url)
            // Uncomment and add your API key if required
            // .header("Authorization", "Bearer YOUR_API_KEY")
            .send()
            .await?;
        let status = response.status();
        tracing::debug!("Received status: {}", status); // Debug the status

        if status.is_success() {
            let body_text = response.text().await?;
            tracing::debug!("Response body: {}", body_text); // Debug the response body

            match serde_json::from_str::<ResponseType>(&body_text) {
                Ok(body) => {
                    tracing::debug!("Deserialized body: {:?}", body); // Debug the deserialized body
                    if let Some(cdn_url) = body.cdn_url {
                        if !cdn_url.is_empty() {
                            tracing::debug!("🔗 Your file is available at: {}", cdn_url); // Debug the cdn_url
                            io::stdout().flush()?;
                            return Ok(cdn_url);
                        }
                    } else if let Some(url) = body.url {
                        tracing::debug!("🔗 Your file is available at: {}", url); // Debug the cdn_url
                        io::stdout().flush()?;
                        return Ok(url);
                    }
                    tracing::debug!("❌ No valid cdn_url or url found, waiting"); // Debug the no valid cdn_url or url found
                    wait_seconds += 1;
                    tracing::debug!("😴 Sleeping for {} seconds", wait_seconds); // Debug the sleep
                    sleep(Duration::from_secs(wait_seconds as u64)).await;
                }
                Err(e) => {
                    tracing::info!("❌ Failed to deserialize response: {}. Body: {}", e, body_text);
                    return Err(anyhow::anyhow!("❌ Deserialization failed: {}", e));
                }
            }
        } else {
            let error_text = response.text().await?;
            tracing::info!("❌ Non-success response: {} - Body: {}", status, error_text);
            return Err(anyhow::anyhow!(
                "API returned non-success status: {}",
                status
            ));
        }
    }

    Err(anyhow::anyhow!(
        "Polling timed out after {} attempts",
        max_attempts
    ))
}
