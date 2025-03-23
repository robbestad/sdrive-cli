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

    println!("File GUID: {}", file_guid); // Debug the GUID

    while !is_finished && wait_seconds < max_attempts {
        let url = format!("https://api.sdrive.app/api/v1/files?guid={}", file_guid);
        println!("Polling URL: {}", url);

        let response = client
            .get(&url)
            // Uncomment and add your API key if required
            // .header("Authorization", "Bearer YOUR_API_KEY")
            .send()
            .await?;
        let status = response.status();
        println!("Received status: {}", status);

        if status.is_success() {
            let body_text = response.text().await?;
            println!("Response body: {}", body_text);

            match serde_json::from_str::<ResponseType>(&body_text) {
                Ok(body) => {
                    println!("Deserialized body: {:?}", body);
                    if let Some(cdn_url) = body.cdn_url {
                        if !cdn_url.is_empty() {
                            println!("Found valid cdn_url: {}", cdn_url);
                            io::stdout().flush()?;
                            return Ok(cdn_url);
                        }
                    } else if let Some(url) = body.url {
                        println!("Found valid url: {}", url);
                        io::stdout().flush()?;
                        return Ok(url);
                    }
                    println!("No valid cdn_url or url found, waiting");
                    wait_seconds += 1;
                    println!("Waiting for {} seconds before next attempt", wait_seconds);
                    sleep(Duration::from_secs(wait_seconds as u64)).await;
                }
                Err(e) => {
                    println!("Failed to deserialize response: {}. Body: {}", e, body_text);
                    return Err(anyhow::anyhow!("Deserialization failed: {}", e));
                }
            }
        } else {
            let error_text = response.text().await?;
            println!("Non-success response: {} - Body: {}", status, error_text);
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
