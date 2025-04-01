use crate::config::{read_config, Config};
use actix_web::{middleware::Logger, web, App, HttpResponse, HttpServer};
use anyhow::Result;
use reqwest::Client;
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use http::header;
mod download;
use actix_governor::{Governor, GovernorConfigBuilder};
use download::{download_file, Args};
use actix_cors::Cors;
use rusqlite::{params, Connection};

use std::collections::HashMap;
mod listfiles;
use listfiles::list_files_handler;
mod watch_directory;
use watch_directory::watch_directory;
mod directories;
use directories::{list_directories_handler, setup_directories_table, list_files_in_directory_handler};


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

pub async fn setup_directories(config: &Arc<Config>) -> Result<()> {
    let sync_dir = PathBuf::from(&config.sync_dir);

    // Definer public og private kataloger
    let public_dir = sync_dir.join("public");
    let private_dir = sync_dir.join("private");

    // Opprett kataloger
    for dir in &[&public_dir, &private_dir] {
        match fs::create_dir_all(dir).await {
            Ok(()) => {
                println!("✅ Directory created or already exists: {}", dir.display());
            }
            Err(e) => {
                println!("❌ Failed to create directory {}: {}", dir.display(), e);
                return Err(anyhow::anyhow!(
                    "Failed to create directory {}: {}",
                    dir.display(),
                    e
                ));
            }
        }
    }

    Ok(())
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

    let pinned_cids = state.pinned_cids.lock().await;
    let _filename_from_cache = pinned_cids.get(&cid.to_string()).cloned();
    drop(pinned_cids);

    let db_conn = state.db_conn.lock().await;
    let mut stmt = db_conn
        .prepare("SELECT filename, file_key FROM pinned_files WHERE cid = ?")
        .unwrap();
    let (filename, file_key) = match stmt.query_row(params![cid.to_string()], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
    }) {
        Ok((filename, file_key)) => (filename, file_key),
        Err(_) => {
            return Ok(
                HttpResponse::NotFound().body(format!("❌ CID {} is not pinned locally", cid))
            )
        }
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

    // Kjør oppsett av kataloger ved oppstart
    setup_directories(&Arc::new(config.clone())).await?;

    if config.api_key.is_empty() || config.user_guid.is_empty() || config.encryption_key.is_empty()
    {
        anyhow::bail!("❌ Missing required configuration. Ensure SDRIVE_API_KEY, SDRIVE_USER_GUID, and SDRIVE_ENCRYPTION_KEY are set or provided in the config file.");
    }

    println!("✅ Config loaded");

    let uploaded_files = Arc::new(Mutex::new(HashSet::new()));
    let pinned_cids = Arc::new(Mutex::new(HashMap::new()));
    let client = Client::new();

    let db_path = format!("{}/.sdrive.db", config.sync_dir);
    let db_conn = Connection::open(&db_path)
        .map_err(|e| anyhow::anyhow!("Failed to open SQLite database: {}", e))?;
    
    // Opprett tabeller
    db_conn.execute(
        "CREATE TABLE IF NOT EXISTS pinned_files (
            cid TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            filepath TEXT UNIQUE NOT NULL,
            file_key TEXT,
            size INTEGER,
            modified INTEGER,
            is_directory BOOLEAN DEFAULT FALSE
        )",
        [],
    )?;

    // Opprett mappe-tabell
    setup_directories_table(&db_conn)?;

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
            watch_directory(
                &config.sync_dir,
                uploaded_files,
                pinned_cids,
                &db_conn,
                &client,
            )
            .await;
        }
    });

    let governor_conf = GovernorConfigBuilder::default()
        .seconds_per_request(60)
        .burst_size(100)
        .finish()
        .unwrap();

    println!("🌏 Starting HTTP server...");
    let port = app_state.config.port;
    println!("📡 Binding to port: {}", port);
    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .wrap(Governor::new(&governor_conf))
            .wrap(Logger::default())
            .wrap(
                Cors::default()
                    .allow_any_origin()
                    .allowed_methods(vec!["GET", "POST"])
                    .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
                    .allow_any_header()
                    .max_age(3600),
            )
            .app_data(web::QueryConfig::default().error_handler(|err, _| {
                actix_web::error::ErrorBadRequest(format!(
                    "❌ Ugyldig format for query-parametre. Eksempel: /download/QmWvMwpQKitV6WsHLMZtpZTDwF4Yr1?key=optional_key\n\nTechnical details: {}",
                    err
                ))
            }))
            .route("/download/{cid}", web::get().to(download_handler))
            .route("/listfiles", web::get().to(list_files_handler))
            .route("/directories", web::get().to(list_directories_handler))
            .route("/directory/files", web::get().to(list_files_in_directory_handler))
    })
    .bind(format!("0.0.0.0:{}", port))
    .map_err(|e| {
        println!("❌ Failed to bind to port {}: {}", port, e);
        e
    })?;
    
    println!("✅ Server bound successfully, starting...");
    println!("🚀 Server is now running on http://0.0.0.0:{}", port);
    println!("📝 Available endpoints:");
    println!("   - GET /download/{{cid}} - Download a file");
    println!("   - GET /listfiles - List all files");
    println!("   - GET /directories - List all directories");
    println!("   - GET /directory/files?path=/path/to/dir - List files in directory");
    println!("👀 Press Ctrl+C to stop the server");
    
    let server = server.run();

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
