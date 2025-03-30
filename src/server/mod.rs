use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use crate::upload::pin_file;
use std::collections::HashSet;
use anyhow::{Result, Context};
use std::sync::Arc;
use std::fmt;
use crate::config::read_config;
use actix_web::{web, App, HttpResponse, HttpServer};
use reqwest::Client;

mod download;
use download::download_file;

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

pub async fn start_server() -> Result<()> {
    println!("🚀 Starting S-Node in server mode...");

    // Henter config
    let config = read_config(None).await?;

    // println!("🔑 API Key: {}", config.api_key);
    // println!("🔑 User GUID: {}", config.user_guid);
    // println!("🔑 Sync Directory: {}", config.sync_dir);
    // println!("🔑 Encryption Key: {}", config.encryption_key);

    if config.api_key.is_empty() || config.user_guid.is_empty() || config.encryption_key.is_empty() {
        anyhow::bail!("❌ Missing required configuration. Ensure SDRIVE_API_KEY, SDRIVE_USER_GUID, and SDRIVE_ENCRYPTION_KEY are set or provided in the config file.");
    }

    println!("✅ Config loaded");

    let uploaded_files = Arc::new(Mutex::new(HashSet::new()));
    let client = Client::new();

    // Spawn directory watcher as a background task
    let watcher_handle = tokio::spawn({
        let config = config.clone();
        let uploaded_files = uploaded_files.clone();
        async move {
            // Run watch_directory and handle its Result to ensure () return
            if let Err(e) = watch_directory(&config.sync_dir, uploaded_files).await {
                println!("❌ Directory watcher failed: {}", e);
            } else {
                println!("📂 Directory watcher completed"); // Only if it naturally exits
            }
        }
    });


    // Start HTTP server
    println!("🌏 Starting HTTP server...");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .route("/download/{cid}", web::get().to(download_handler))
    })
    .bind("0.0.0.0:8081")?
    .run();

    // Run server and wait for Ctrl+C
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                println!("❌ Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("👋 Shutdown signal received, stopping...");
            watcher_handle.abort(); // Stop the watcher
        }
    }

    Ok(())
}
