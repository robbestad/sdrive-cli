use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use toml;
use crate::upload::pin_file;
use std::collections::HashSet;
use anyhow::{Result, Context};
use std::sync::Arc;
use std::fmt;
use keyring::Entry;
use std::env;
use crate::config::read_config;
use actix_web::{web, App, HttpResponse, HttpServer};
use crate::server::download::download_file; // Import the function
use reqwest::Client;

#[derive(Serialize, Deserialize, Debug)]
struct Config {
    api_key: String,
    user_guid: String,
    sync_dir: String,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "api_key: [REDACTED], user_guid: {}, sync_dir: {}",
            self.user_guid, self.sync_dir
        )
    }
}

// 🚀 Overvåker en mappe og laster opp filer automatisk
pub async fn watch_directory(sync_dir: &str, uploaded_files: Arc<Mutex<HashSet<PathBuf>>>) {
    let sync_path = PathBuf::from(sync_dir);

    loop {
        match fs::read_dir(&sync_path).await {
            Ok(mut entries) => {
                while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
                    let file_path = entry.path();

                    if file_path.is_file() {
                        let mut uploaded_files_guard = uploaded_files.lock().await;

                        if uploaded_files_guard.contains(&file_path) {
                            continue;
                        }

                        println!("📂 New file detected: {:?}", file_path);

                        let unencrypted = false;

                        match pin_file(
                            file_path.clone(),
                            unencrypted
                        ).await {
                            Ok(_) => {
                                println!("✅ Successfully uploaded: {:?}", file_path);
                                uploaded_files_guard.insert(file_path);
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to upload file {:?}: {}", file_path, e);
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("⚠️ Error reading directory {}: {}", sync_dir, e);
            }
        }

        sleep(Duration::from_secs(10)).await;
    }
}

async fn download_handler(
    cid: web::Path<String>,
    client: web::Data<Client>,
) -> HttpResponse {
    match download_file(&client, &cid, None).await {
        Ok(data) => HttpResponse::Ok()
            .content_type("application/octet-stream")
            .body(data),
        Err(e) => HttpResponse::InternalServerError().body(format!("Download failed: {}", e)),
    }
}

// 🚀 Starter serveren og begynner å overvåke filer
pub async fn start_server() -> Result<()> {
    println!("🚀 Starting S-Node in server mode...");
    let client = Client::new();
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone())) // Share the client
            .route("/download/{cid}", web::get().to(download_handler))
    })
    .bind("0.0.0.0:8081")? // Different port from IPFS gateway (8080)
    .run()
    .await?;

    // Henter config, automatisk fra miljøvariabler, fallback til config.toml
    let config = read_config(None).await?;

    if config.api_key.is_empty() || config.user_guid.is_empty() || config.encryption_key.is_empty() {
        anyhow::bail!("❌ Missing required configuration. Ensure API_KEY, USER_GUID, and ENCRYPTION_KEY are set.");
    }

    println!("✅ Config loaded");

    let uploaded_files = Arc::new(Mutex::new(HashSet::new()));

    tokio::select! {
        _ = watch_directory(&config.sync_dir, uploaded_files.clone()) => {},
        _ = tokio::signal::ctrl_c() => {
            println!("👋 Shutdown signal received, exiting...");
        },
    }

    Ok(())
}
