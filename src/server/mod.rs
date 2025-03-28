use std::path::PathBuf;
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};
use toml;
use crate::upload::upload_file;
use std::collections::HashSet;
use anyhow::{Result, Context};
use std::sync::Arc;
use std::fmt;
use keyring::Entry;
use std::env;


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


async fn load_encryption_key() -> Result<String> {
    // 🎯 1️⃣ Prøv først å hente nøkkelen fra miljøvariabelen
    if let Ok(enc_key) = env::var("SDRIVE_ENCRYPTION_KEY") {
        return Ok(enc_key);
    }

    // 🔐 2️⃣ Hvis ikke, prøv å hente fra systemets keyring
    let entry = Entry::new("sdrive", "encryption_key").context("Failed to access keyring")?;
    match entry.get_password() {
        Ok(password) => Ok(password),
        Err(_) => anyhow::bail!(
            "❌ Encryption key not found! Set SDRIVE_ENCRYPTION_KEY env variable or store it in keyring."
        ),
    }
}
// 🚀 Laster inn og validerer konfigurasjonen
async fn load_config(path: &str) -> Result<Config> {
    let config_content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("⚠️ Failed to read config file at {}", path))?;

    let mut config: Config = toml::from_str(&config_content)
        .with_context(|| "⚠️ Failed to parse config file")?;

    // 🔑 Henter API-nøkkel fra env eller config
    if let Ok(api_key) = env::var("SDRIVE_API_KEY") {
        config.api_key = api_key;
    }

    if let Ok(user_guid) = env::var("SDRIVE_USER_GUID") {
        config.user_guid = user_guid;
    }

    // 🔐 Henter krypteringsnøkkel fra env eller keyring
    let encryption_key = load_encryption_key().await?;
    
    println!("✅ Config loaded successfully.");
    println!("🔑 Encryption key loaded successfully.");

    Ok(config)
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
                        let overwrite = false;
                        let parent_folder = sync_path.clone();
                        let config_path = PathBuf::from("/config/config.toml");

                        match upload_file(
                            file_path.clone(),
                            parent_folder,
                            config_path.to_string_lossy().to_string(),
                            unencrypted,
                            overwrite
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

// 🚀 Starter serveren og begynner å overvåke filer
pub async fn start_server() -> Result<()> {
    let config = load_config("/config/config.toml").await?;
    println!("🚀 Starting S-Node in server mode...");

    let uploaded_files = Arc::new(Mutex::new(HashSet::new()));

    tokio::select! {
        _ = watch_directory(&config.sync_dir, uploaded_files.clone()) => {},
        _ = tokio::signal::ctrl_c() => {
            println!("👋 Shutdown signal received, exiting...");
        },
    }

    Ok(())
}
