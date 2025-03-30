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
use ignore::gitignore::GitignoreBuilder;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::HashMap;

#[derive(Serialize)]
struct MetadataPayload {
    cid: String,
    filename: String,
    filepath: String,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    config: Arc<Config>,
    db_conn: Arc<Mutex<Connection>>,
    pinned_cids: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(serde::Deserialize)]
struct DownloadQuery {
    filepath: Option<String>,
    key: Option<String>,
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

async fn store_metadata_global(client: &Client, cid: String, filename: String, filepath: String) -> Result<()> {
    let payload = MetadataPayload { cid, filename, filepath };
    client
        .post("https://backend.sdrive.app/metadatastore")
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store metadata globally: {}", e))?;
    println!("✅ Stored metadata globally for CID: {}", payload.cid);
    Ok(())
}

// 🚀 Overvåker en mappe og laster opp filer automatisk
pub async fn watch_directory(
    sync_dir: &str,
    uploaded_files: Arc<Mutex<HashSet<PathBuf>>>,
    pinned_cids: Arc<Mutex<HashMap<String, String>>>,
    db_conn: &Arc<Mutex<Connection>>,
    client: &Client,
) {
    let sync_path = PathBuf::from(sync_dir);
    let ignore_file = sync_path.join(".sdrive-ignore");

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

                        if gitignore.matched(&file_path, file_path.is_dir()).is_ignore() {
                            continue;
                        }

                        if file_path.is_dir() || file_path.extension().unwrap_or_default() == ".DS_Store" {
                            continue;
                        }

                        let db_conn = db_conn.lock().await;
                        let filepath_str = file_path.to_string_lossy().to_string();
                        let exists = db_conn
                            .query_row(
                                "SELECT COUNT(*) FROM pinned_files WHERE filepath = ?",
                                params![filepath_str],
                                |row| row.get::<_, i32>(0),
                            )
                            .map(|count| count > 0)
                            .unwrap_or(false);

                        if exists {
                            println!("📂 Ignored duplicate file: {:?}", file_path);
                            uploaded_files_guard.insert(file_path.clone());
                            continue;
                        }

                        println!("📂 New file detected: {:?}", file_path);

                        let unencrypted = false;

                        match pin_file(file_path.clone(), unencrypted).await {
                            Ok((cid, file_key)) => {
                                println!("✅ Successfully uploaded: {:?}", file_path);
                                uploaded_files_guard.insert(file_path.clone());
                                let filename = file_path.file_name().unwrap().to_string_lossy().to_string();

                                db_conn.execute(
                                    "INSERT OR REPLACE INTO pinned_files (cid, filename, filepath, file_key) VALUES (?, ?, ?, ?)",
                                    params![cid, filename, filepath_str, file_key],
                                ).unwrap();

                                if let Err(e) = store_metadata_global(client, cid.clone(), filename.clone(), filepath_str.clone()).await {
                                    eprintln!("⚠️ Failed to store metadata globally: {}", e);
                                }

                                let mut pinned_cids_guard = pinned_cids.lock().await;
                                pinned_cids_guard.insert(cid.clone(), filename.clone());
                                println!("✅ Added CID to cache and DB: {} with name {}", cid, filename);
                            }
                            Err(e) => {
                                eprintln!("❌ Failed to upload file {:?}: {}", file_path, e);
                            }
                        }
                        drop(db_conn);
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
        return Ok(HttpResponse::BadRequest().body("❌ CID er påkrevd. Eksempel: /download/QmWvMwpQKitV6WsHLMZtpZTDwF4Yr1"));
    }

    let pinned_cids = state.pinned_cids.lock().await;
    let _filename_from_cache = pinned_cids.get(&cid.to_string()).cloned();
    drop(pinned_cids);

    let db_conn = state.db_conn.lock().await;
    let mut stmt = db_conn.prepare("SELECT filename, file_key FROM pinned_files WHERE cid = ?").unwrap();
    let (filename, file_key) = match stmt.query_row(params![cid.to_string()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok((filename, file_key)) => (filename, file_key),
        Err(_) => return Ok(HttpResponse::NotFound().body(format!("❌ CID {} is not pinned locally", cid))),
    };

    let key = query.key.clone(); // Use query key if provided, else None

    println!("🔍 Received key in handler: {:?}", query.key);
    println!("🔍 DB key: {:?}", file_key);
    println!("🔍 Using key (from query or DB): {:?}", key);

    let args = Args {
        output: None,
        key,
        filename: cid.to_string(),
        filepath: query.filepath.clone().unwrap_or_default(),
    };

    match download_file(&state.client, &cid, &args, &state.config).await {
        Ok(data) => {
            let filename = if !args.filepath.is_empty() {
                args.filepath.clone()
            } else {
                filename
            };
            Ok(HttpResponse::Ok()
                .content_type("application/octet-stream")
                .append_header(("Content-Disposition", format!("attachment; filename=\"{}\"", filename)))
                .body(data))
        }
        Err(e) => Ok(HttpResponse::NotFound().body(format!("❌ Nedlasting feilet: {}", e))),
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
    let pinned_cids = Arc::new(Mutex::new(HashMap::new()));
    let client = Client::new();

    let db_path = format!("{}/.sdrive.db", config.sync_dir);
    let db_conn = Connection::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to open SQLite database: {}", e))?;
    db_conn.execute(
        "CREATE TABLE IF NOT EXISTS pinned_files (
            cid TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            filepath TEXT UNIQUE NOT NULL,
            file_key TEXT
        )",
        [],
    )?;
    let db_conn = Arc::new(Mutex::new(db_conn));

    let app_state = AppState {
        client,
        config: Arc::new(config.clone()),
        db_conn,
        pinned_cids: pinned_cids.clone(),
    };

    let watcher_handle = tokio::spawn({
        let config = app_state.config.clone();
        let uploaded_files = uploaded_files.clone();
        let db_conn = app_state.db_conn.clone();
        let pinned_cids = pinned_cids.clone();
        let client = app_state.client.clone();
        async move {
            watch_directory(&config.sync_dir, uploaded_files, pinned_cids, &db_conn, &client).await;
        }
    });

    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(60)
        .burst_size(100)
        .finish()
        .unwrap();

    println!("🌏 Starting HTTP server...");
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Governor::new(&governor_conf))
            .wrap(Logger::default())
            .app_data(web::QueryConfig::default().error_handler(|err, _| {
                actix_web::error::ErrorBadRequest(format!(
                    "❌ Ugyldig format for query-parametre. Eksempel: /download/QmWvMwpQKitV6WsHLMZtpZTDwF4Yr1?key=optional_key\n\nTechnical details: {}",
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
