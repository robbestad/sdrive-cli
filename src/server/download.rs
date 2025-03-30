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

// Your main function (updated)
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    // ... (log setup unchanged)

    match cli.command {
        // ... (other commands unchanged)
        Commands::Download(args) => {
            let client = Client::new();
            let parsed_url = Url::parse(&args.url)?;
            let host = parsed_url.host_str().unwrap_or("");

            if host != "cdn.sdrive.pro" && host != "ipfs.sdrive.pro" {
                return Err(anyhow::anyhow!(
                    "URL must be from cdn.sdrive.pro or ipfs.sdrive.pro"
                ));
            }

            let mut encrypted_data = None;
            let mut original_filename = String::new();

            match host {
                "cdn.sdrive.pro" => {
                    // ... (CDN logic unchanged)
                }
                "ipfs.sdrive.pro" => {
                    let guid = parsed_url
                        .path_segments()
                        .and_then(|mut segments| segments.nth(1))
                        .ok_or_else(|| anyhow::anyhow!("Missing GUID in IPFS URL"))?;

                    // Use the extracted function
                    encrypted_data = Some(
                        download_file(&client, guid, args.output.clone())
                            .await?,
                    );
                    original_filename = "downloaded".to_string(); // Adjust as needed
                }
                _ => unreachable!(),
            };

            let encrypted_data = encrypted_data.expect("Encrypted data should be set by now");
            // ... (decryption and saving logic unchanged)
        }
        Commands::Server => {
            start_server().await?;
        }
        // ... (other commands unchanged)
    }
    Ok(())
}