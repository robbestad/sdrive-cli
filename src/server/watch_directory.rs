use std::path::PathBuf;
use tokio::sync::Mutex;
use std::time::Duration;
use std::collections::{HashMap, HashSet};
use tokio::fs;
use rusqlite::params;
use reqwest::Client;
use rusqlite::Connection;
use serde::Serialize;
use crate::file::is_ignored;
use crate::upload::pin_file;
use anyhow::Result;
use std::sync::Arc;
use crate::server::directories::update_directory;
use crate::config::Config;
use crate::server::directories::normalize_path;

#[derive(Serialize)]
struct MetadataPayload {
    cid: String,
    filename: String,
    filepath: String,
}

#[derive(Serialize)]
struct UnpinPayload {
    cid: String,
    user_guid: String,
}

async fn unpin_file_remote(cid: String, config: &Config) -> Result<()> {
    let client = Client::new();
    let url = format!("https://backend.sdrive.app/unpin");
    let payload = UnpinPayload {
        cid,
        user_guid: config.user_guid.clone(),
    };
    
    let response = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", config.api_key))
        .json(&payload)
        .send()
        .await?;
    
    if !response.status().is_success() {
        return Err(anyhow::anyhow!("Failed to unpin file: {}", response.status()));
    }
    
    Ok(())
}

async fn store_metadata_global(
    client: &Client,
    cid: String,
    filename: String,
    filepath: String,
) -> Result<()> {
    let payload = MetadataPayload {
        cid,
        filename,
        filepath,
    };
    client
        .post("https://backend.sdrive.app/metadatastore")
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to store metadata globally: {}", e))?;
    println!("✅ Stored metadata globally for CID: {}", payload.cid);
    Ok(())
}

// 🚀 Overvåker mapper og laster opp filer automatisk
pub async fn watch_directory(
    sync_dir: &str,
    uploaded_files: Arc<Mutex<HashSet<PathBuf>>>,
    pinned_cids: Arc<Mutex<HashMap<String, String>>>,
    db_conn: &Arc<Mutex<Connection>>,
    client: &Client,
    _config: &Config,
) {
    let sync_path = PathBuf::from(sync_dir);
    let public_path = sync_path.join("public");
    let private_path = sync_path.join("private");

    println!("📂 Sync path: {}", sync_path.display());
    println!("📂 Public path: {}", public_path.display());
    println!("📂 Private path: {}", private_path.display());

    loop {
        // Først sjekk etter slettede filer og mapper
        let mut deleted_files = Vec::new();
        let mut deleted_dirs = Vec::new();

        // Hent alle filer fra databasen
        {
            let db_conn_guard = db_conn.lock().await;
            let mut stmt = db_conn_guard
                .prepare("SELECT cid, filepath FROM pinned_files")
                .unwrap();
            let files: Vec<(String, String)> = stmt
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            // Sjekk hver fil
            for (cid, filepath) in files {
                let local_path = PathBuf::from(filepath.replace("/data/sdrive", sync_dir));

                tracing::trace!("🔍 Checking file existence:");
                tracing::trace!("   Database path: {}", filepath);
                tracing::trace!("   Local path: {}", local_path.display());
                let canonical_path = local_path.canonicalize().unwrap_or(local_path.clone());
                tracing::trace!("   Absolute path: {}", canonical_path.display());
                
                if !local_path.exists() {
                    tracing::info!("❌ File not found: {}", local_path.display());
                    deleted_files.push((cid, filepath));
                } else {
                    tracing::info!("✅ File exists: {}", local_path.display());
                }
            }
        }

        // Hent alle mapper fra databasen
        {
            let db_conn_guard = db_conn.lock().await;
            let mut stmt = db_conn_guard
                .prepare("SELECT path FROM directories")
                .unwrap();
            let dirs: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();

            // Sjekk hver mappe
            for dirpath in dirs {
                let local_path = PathBuf::from(dirpath.replace("/data/sdrive", sync_dir));

                let canonical_path = local_path.canonicalize().unwrap_or(local_path.clone());
                tracing::trace!("🔍 Checking directory existence:");
                tracing::trace!("   Database path: {}", dirpath);
                tracing::trace!("   Local path: {}", local_path.display());
                tracing::trace!("   Absolute path: {}", canonical_path.display());
                
                if !local_path.exists() {
                    tracing::info!("❌ Directory not found: {}", local_path.display());
                    deleted_dirs.push(dirpath);
                } else {
                    tracing::info!("✅ Directory exists: {}", local_path.display());
                }
            }
        }

        // Håndter slettede filer
        for (cid, filepath) in deleted_files {
            println!("🗑️ Found deleted file: {}", filepath);
            
            // Unpin fra IPFS
            if let Err(e) = client
                .post("http://127.0.0.1:5002/api/v0/pin/rm")
                .query(&[("arg", &cid)])
                .send()
                .await
            {
                eprintln!("⚠️ Failed to unpin file from IPFS: {}", e);
            }

            // Unpin fra SDrive IPFS hvis abonnement er aktivt
            let has_subscription = false;
            if has_subscription {
                if let Err(e) = unpin_file_remote(cid, _config).await {
                    eprintln!("⚠️ Failed to unpin file from SDrive network: {}", e);
                }
            } else {
                println!("💸 You need an active subscription to unpin files from the SDrive network.");
            }

            // Fjern fra databasen
            let db_conn_guard = db_conn.lock().await;
            if let Err(e) = db_conn_guard.execute(
                "DELETE FROM pinned_files WHERE filepath = ?",
                params![filepath],
            ) {
                eprintln!("⚠️ Failed to remove file from database: {}", e);
            }
        }

        // Håndter slettede mapper
        for dirpath in deleted_dirs {
            println!("🗑️ Found deleted directory: {}", dirpath);
            
            // Fjern fra databasen
            let db_conn_guard = db_conn.lock().await;
            if let Err(e) = db_conn_guard.execute(
                "DELETE FROM directories WHERE path = ?",
                params![dirpath],
            ) {
                eprintln!("⚠️ Failed to remove directory from database: {}", e);
            }
        }

        // Fortsett med normal overvåking av mapper
        for (path, unencrypted) in [(public_path.clone(), true), (private_path.clone(), false)] {
            let mut dirs = vec![path];

            while let Some(current_dir) = dirs.pop() {
                match fs::read_dir(&current_dir).await {
                    Ok(mut entries) => {
                        // Først sjekk om mappen eksisterer i databasen
                        let current_dir_str = normalize_path(&current_dir.to_string_lossy());
                        let dir_exists = {
                            let db_conn_guard = db_conn.lock().await;
                            db_conn_guard
                                .query_row(
                                    "SELECT COUNT(*) FROM directories WHERE path = ?",
                                    params![current_dir_str],
                                    |row| row.get::<_, i32>(0),
                                )
                                .map(|count| count > 0)
                                .unwrap_or(false)
                        };

                        // Hvis mappen ikke eksisterer, legg den til
                        if !dir_exists {
                            if let Err(e) = update_directory(db_conn, &current_dir, unencrypted).await {
                                eprintln!("⚠️ Failed to update directory in database: {}", e);
                            }
                        }

                        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
                            let file_path = entry.path();

                            if is_ignored(&sync_path, &file_path).await {
                                tracing::trace!("⏭️ Skipping ignored file: {}", &file_path.display());
                                continue;
                            }

                            if file_path.is_dir() {
                                dirs.push(file_path.clone());
                                
                                let filepath_str = normalize_path(&file_path.to_string_lossy());
                                let filename = file_path
                                    .file_name()
                                    .unwrap()
                                    .to_string_lossy()
                                    .to_string();
                                let modified = file_path
                                    .metadata()
                                    .unwrap()
                                    .modified()
                                    .unwrap()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs();
                                if let Err(e) = update_directory(db_conn, &file_path, unencrypted).await {
                                    eprintln!("⚠️ Failed to update directory in database: {}", e);
                                }

                                {
                                    let db_conn_guard = db_conn.lock().await;
                                    db_conn_guard.execute(
                                        "INSERT OR REPLACE INTO pinned_files (cid, filename, filepath, size, modified, is_directory) VALUES (?, ?, ?, ?, ?, ?)",
                                        params!["", filename, filepath_str, 0, modified, true],
                                    ).unwrap();
                                }
                                
                                continue;
                            }

                            let mut uploaded_files_guard = uploaded_files.lock().await;
                            if uploaded_files_guard.contains(&file_path) {
                                continue;
                            }

                            let filepath_str = normalize_path(&file_path.to_string_lossy());
                            let exists = {
                                let db_conn_guard = db_conn.lock().await;
                                db_conn_guard
                                    .query_row(
                                        "SELECT COUNT(*) FROM pinned_files WHERE filepath = ?",
                                        params![filepath_str],
                                        |row| row.get::<_, i32>(0),
                                    )
                                    .map(|count| count > 0)
                                    .unwrap_or(false)
                            };

                            if exists {
                                tracing::trace!("📂 Ignored duplicate file: {:?}", file_path);
                                uploaded_files_guard.insert(file_path.clone());
                                continue;
                            }

                            println!("📂 New file detected: {:?}", file_path);

                            match pin_file(file_path.clone(), unencrypted).await {
                                Ok((cid, file_key)) => {
                                    println!("✅ Successfully uploaded: {:?}", file_path);
                                    uploaded_files_guard.insert(file_path.clone());
                                    let filename = file_path
                                        .file_name()
                                        .unwrap()
                                        .to_string_lossy()
                                        .to_string();
                                    let size = file_path.metadata().unwrap().len();
                                    let modified = file_path
                                        .metadata()
                                        .unwrap()
                                        .modified()
                                        .unwrap()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();

                                    {
                                        let db_conn_guard = db_conn.lock().await;
                                        db_conn_guard.execute(
                                            "INSERT OR REPLACE INTO pinned_files (cid, filename, filepath, file_key, size, modified, is_directory) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                            params![cid, filename, filepath_str, file_key, size, modified, false],
                                        ).unwrap();
                                        println!("✅ Lagret file_key i databasen: {}", file_key);
                                    }

                                    if let Err(e) = store_metadata_global(
                                        client,
                                        cid.clone(),
                                        filename.clone(),
                                        filepath_str.clone(),
                                    )
                                    .await
                                    {
                                        eprintln!("⚠️ Failed to store metadata globally: {}", e);
                                    }

                                    let mut pinned_cids_guard = pinned_cids.lock().await;
                                    pinned_cids_guard.insert(cid.clone(), filename.clone());
                                    println!(
                                        "✅ Added CID to cache and DB: {} with name {}",
                                        cid, filename
                                    );
                                }
                                Err(e) => {
                                    eprintln!("❌ Failed to upload file {:?}: {}", file_path, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️ Error reading directory {:?}: {}", current_dir, e);
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
