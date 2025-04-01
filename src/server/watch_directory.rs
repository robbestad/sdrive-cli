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
    config: &Config,
) {
    let sync_path = PathBuf::from(sync_dir);
    let public_path = sync_path.join("public");
    let private_path = sync_path.join("private");

    loop {
        for (path, unencrypted) in [(public_path.clone(), true), (private_path.clone(), false)] {
            let mut dirs = vec![path];

            while let Some(current_dir) = dirs.pop() {
                match fs::read_dir(&current_dir).await {
                    Ok(mut entries) => {
                        // Først sjekk om mappen eksisterer i databasen
                        let current_dir_str = normalize_path(&current_dir.to_string_lossy());
                        let db_conn_guard = db_conn.lock().await;
                        let dir_exists = db_conn_guard
                            .query_row(
                                "SELECT COUNT(*) FROM directories WHERE path = ?",
                                params![current_dir_str],
                                |row| row.get::<_, i32>(0),
                            )
                            .map(|count| count > 0)
                            .unwrap_or(false);
                        drop(db_conn_guard);

                        // Hvis mappen ikke eksisterer, legg den til
                        if !dir_exists {
                            if let Err(e) = update_directory(db_conn, &current_dir, unencrypted).await {
                                eprintln!("⚠️ Failed to update directory in database: {}", e);
                            }
                        }

                        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
                            let file_path = entry.path();

                            if is_ignored(&sync_path, &file_path).await {
                                println!("⏭️ Skipping ignored file: {}", &file_path.display());
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

                                let db_conn_guard = db_conn.lock().await;
                                db_conn_guard.execute(
                                    "INSERT OR REPLACE INTO pinned_files (cid, filename, filepath, size, modified, is_directory) VALUES (?, ?, ?, ?, ?, ?)",
                                    params!["", filename, filepath_str, 0, modified, true],
                                ).unwrap();
                                
                                continue;
                            }

                            let mut uploaded_files_guard = uploaded_files.lock().await;
                            if uploaded_files_guard.contains(&file_path) {
                                continue;
                            }

                            let filepath_str = normalize_path(&file_path.to_string_lossy());
                            let db_conn_guard = db_conn.lock().await;
                            let exists = db_conn_guard
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

                                    db_conn_guard.execute(
                                        "INSERT OR REPLACE INTO pinned_files (cid, filename, filepath, file_key, size, modified, is_directory) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                        params![cid, filename, filepath_str, file_key, size, modified, false],
                                    ).unwrap();

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
