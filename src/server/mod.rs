use crate::config::{read_config, Config};
use crate::upload::pin_file;
use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer};
use anyhow::Result;
use reqwest::Client;
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;
mod download;
use actix_governor::{Governor, GovernorConfigBuilder};
use download::{download_file, Args};
use ignore::gitignore::{Gitignore, GitignoreBuilder}; // Add rate limiting

// App state struct to hold both Client and Config
#[derive(Clone)]
struct AppState {
    client: Client,
    config: Arc<Config>,
    pinned_cids: Arc<Mutex<HashSet<String>>>, // Cache of pinned CIDs
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
pub async fn watch_directory(
    sync_dir: &str,
    uploaded_files: Arc<Mutex<HashSet<PathBuf>>>,
    pinned_cids: Arc<Mutex<HashSet<String>>>,
) {
    let sync_path = PathBuf::from(sync_dir);
    let ignore_file = sync_path.join(".sdrive-ignore");
    // Load .sdrive-ignore
    let mut gitignore_builder = GitignoreBuilder::new(&sync_path);
    if ignore_file.exists() {
        let contents = fs::read_to_string(&ignore_file).await.unwrap_or_default();
        for line in contents.lines() {
            if !line.trim().is_empty() && !line.starts_with('#') {
                gitignore_builder
                    .add_line(None, line)
                    .expect("Failed to add ignore pattern");
            }
        }
    } else {
        // Default ignores if no .sdrive-ignore exists
        gitignore_builder
            .add_line(None, ".DS_Store")
            .expect("Failed to add default ignore");
    }
    let gitignore = gitignore_builder
        .build()
        .expect("Failed to build gitignore");

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
                        // Check against .sdrive-ignore
                        if gitignore
                            .matched(&file_path, file_path.is_dir())
                            .is_ignore()
                        {
                            println!("📂 Ignored file: {:?}", file_path);
                            continue;
                        }

                        if file_path.is_dir()
                            || file_path.extension().unwrap_or_default() == ".DS_Store"
                        {
                            continue;
                        }

                        println!("📂 New file detected: {:?}", file_path);

                        let unencrypted = false;

                        match pin_file(file_path.clone(), unencrypted).await {
                            Ok(cid) => {
                                println!("✅ Successfully uploaded: {:?}", file_path);
                                uploaded_files_guard.insert(file_path);
                                let mut pinned_cids_guard = pinned_cids.lock().await;
                                pinned_cids_guard.insert(cid.clone());
                                println!("✅ Added CID to cache: {}", cid);
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

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

async fn download_handler(
    cid: web::Path<String>,
    query: web::Query<DownloadQuery>,
    state: web::Data<AppState>,
) -> Result<HttpResponse, actix_web::Error> {
    if cid.is_empty() {
        return Ok(HttpResponse::BadRequest()
            .body("❌ CID er påkrevd. Eksempel: /download/QmWvMwpQKitV6WsHLMZtpZTDwF4Yr1"));
    }

    // Fast CID check from cache
    let pinned_cids = state.pinned_cids.lock().await;
    if !pinned_cids.contains(&cid.to_string()) {
        return Ok(HttpResponse::NotFound().body(format!("❌ CID {} is not pinned locally", cid)));
    }
    drop(pinned_cids); // Release lock early

    let is_encrypted = query.encrypted.unwrap_or(false);
    let key = query.encryption_key.clone();

    println!("🔍 Received key in handler: {:?}", key);

    if is_encrypted && key.is_none() {
        println!("⚠️ No encryption key provided; using master key from keyring.");
    }

    let args = Args {
        output: None,
        encrypted: is_encrypted,
        key,
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
                .append_header((
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                ))
                .body(data))
        }
        Err(e) => Ok(HttpResponse::NotFound().body(format!("❌ Nedlasting feilet: {}", e))),
    }
}

pub async fn start_server() -> Result<()> {
    println!("🚀 Starting S-Node in server mode...");
    let config = read_config(None).await?;

    if config.api_key.is_empty() || config.user_guid.is_empty() || config.encryption_key.is_empty()
    {
        anyhow::bail!("❌ Missing required configuration. Ensure SDRIVE_API_KEY, SDRIVE_USER_GUID, and SDRIVE_ENCRYPTION_KEY are set or provided in the config file.");
    }

    println!("✅ Config loaded");

    let uploaded_files = Arc::new(Mutex::new(HashSet::new()));
    let pinned_cids = Arc::new(Mutex::new(HashSet::new()));
    let client = Client::new();
    let app_state = AppState {
        client,
        config: Arc::new(config.clone()),
        pinned_cids: pinned_cids.clone(),
    };

    let watcher_handle = tokio::spawn({
        let config = app_state.config.clone();
        let uploaded_files = uploaded_files.clone();
        let pinned_cids = pinned_cids.clone();
        async move {
            watch_directory(&config.sync_dir, uploaded_files, pinned_cids).await;
        }
    });

    // Rate limiting: 100 requests per minute per IP
    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(60) // 100 requests per minute
        .burst_size(100)
        .finish()
        .unwrap();

    println!("🌏 Starting HTTP server...");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Governor::new(&governor_conf)) // Add rate limiting
            .wrap(Logger::default()) // Add logging for debugging
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
