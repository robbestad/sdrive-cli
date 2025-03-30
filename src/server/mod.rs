use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use crate::upload::pin_file;
use std::collections::HashSet;
use std::sync::Arc;
use std::fmt;
use crate::config::{read_config, Config};
use actix_web::{web, App, HttpResponse, HttpServer};
use anyhow::Result;
use reqwest::Client;
mod download;
use download::{download_file, Args};


// App state struct to hold both Client and Config
#[derive(Clone)]
struct AppState {
    client: Client,
    config: Arc<Config>,
}

#[derive(serde::Deserialize)]
struct DownloadQuery {
    filepath: Option<String>,
    encrypted: Option<bool>,
    encryption_key: Option<String>,
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

                        // Skippe mapper. Fiks dette senere.    
                        if file_path.is_dir() {
                            continue;
                        }

                        // Skippe .DS_Store filer   
                        if file_path.extension().unwrap_or_default() == ".DS_Store" {
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
    query: web::Query<DownloadQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    if cid.is_empty() {
        return Ok(HttpResponse::BadRequest().body("❌ CID er påkrevd. Eksempel: /download/QmWvMwpQKitV6WsHLMZtpZTDwF4Yr1"));
    }

    let is_encrypted = query.encrypted.unwrap_or(false);
    let key = query.encryption_key.clone();

    if is_encrypted && key.is_none() {
        println!("⚠️ No encryption key provided; using master key from keyring.");
    }

    let args = Args {
        output: None,
        encrypted: is_encrypted,
        key, // Pass the raw key as received
        filename: cid.to_string(),
        filepath: query.filepath.clone().unwrap_or_default(),
    };

    match download_file(&state.client, &cid, &args, &state.config).await {
        Ok(data) => {
            let filename = if !args.filepath.is_empty() {
                args.filepath.clone()
            } else {
                cid.to_string()
            };
            Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .append_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(data))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().body(format!("❌ Nedlasting feilet: {}", e))),
    }
}

pub async fn start_server() -> Result<()> {
    println!("🚀 Starting S-Node in server mode...");
    let config = read_config(None).await?;

    if config.api_key.is_empty() || config.user_guid.is_empty() || config.encryption_key.is_empty() {
        anyhow::bail!("❌ Missing required configuration. Ensure SDRIVE_API_KEY, SDRIVE_USER_GUID, and SDRIVE_ENCRYPTION_KEY are set or provided in the config file.");
    }

    println!("✅ Config loaded");

    let uploaded_files = Arc::new(Mutex::new(HashSet::new()));
    let client = Client::new();
    let app_state = AppState {
        client,
        config: Arc::new(config),
    };

    let watcher_handle = tokio::spawn({
        let config = app_state.config.clone();
        let uploaded_files = uploaded_files.clone();
        async move {
            watch_directory(&config.sync_dir, uploaded_files).await;
        }
    });

    println!("🌏 Starting HTTP server...");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .app_data(web::QueryConfig::default().error_handler(|err, _| {
                actix_web::error::ErrorBadRequest(format!(
                    "❌ Ugyldig format for query-parametre. Eksempel: /download/QmWvMwpQKitV6WsHLMZtpZTDwF4Yr1?encrypted=true&encryption_key=din_nøkkel\n\nTeknisk detalj: {}",
                    err
                ))
            }))
            .route("/download/{cid}", web::get().to(download_handler))
    })
    .bind("0.0.0.0:8081")?
    .run();

    tokio::select! {
        result = server => {
            if let Err(e) = result {
                println!("❌ Server error: {}", e);
            }
        }
        _ = tokio::signal::ctrl_c() => {
            println!("👋 Shutdown signal received, stopping...");
            watcher_handle.abort();
        }
    }

    Ok(())
}