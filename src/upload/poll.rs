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
    let mut wait_seconds = 0;
    let max_attempts = 10;

    tracing::debug!("File GUID: {}", file_guid);

    for attempt in 1..=max_attempts {
        let url = format!("https://api.sdrive.app/api/v1/files?guid={}", file_guid);
        tracing::debug!("Polling URL: {}", url);

        let response = client
            .get(&url)
            // .header("Authorization", "Bearer YOUR_API_KEY") // Uncomment if needed
            .send()
            .await?;
        let status = response.status();
        tracing::debug!("Received status: {}", status);

        if status.is_success() {
            let body_text = response.text().await?;
            tracing::debug!("Raw response body: '{}'", body_text);

            if body_text.trim().is_empty() {
                tracing::debug!("Response body is empty, retrying...");
                wait_seconds += 1;
                tracing::debug!("😴 Sleeping for {} seconds (attempt {}/{})", wait_seconds, attempt, max_attempts);
                sleep(Duration::from_secs(wait_seconds as u64)).await;
                continue;
            }

            match serde_json::from_str::<ResponseType>(&body_text) {
                Ok(body) => {
                    tracing::debug!("Deserialized body: {:?}", body);
                    if let Some(cdn_url) = body.cdn_url {
                        if !cdn_url.is_empty() {
                            tracing::debug!("🔗 Your file is available at: {}", cdn_url);
                            io::stdout().flush()?;
                            return Ok(cdn_url);
                        }
                    } else if let Some(url) = body.url {
                        tracing::debug!("🔗 Your file is available at: {}", url);
                        io::stdout().flush()?;
                        return Ok(url);
                    }
                    tracing::debug!("❌ No valid cdn_url or url found, retrying...");
                    wait_seconds += 1;
                    tracing::debug!("😴 Sleeping for {} seconds (attempt {}/{})", wait_seconds, attempt, max_attempts);
                    sleep(Duration::from_secs(wait_seconds as u64)).await;
                }
                Err(e) => {
                    tracing::info!(
                        "❌ Failed to deserialize response: {}. Body: '{}'",
                        e,
                        body_text
                    );
                    return Err(anyhow::anyhow!("❌ Deserialization failed: {}", e));
                }
            }
        } else {
            let error_text = response.text().await?;
            tracing::info!("❌ Non-success response: {} - Body: '{}'", status, error_text);
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