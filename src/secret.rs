use crate::config::read_config;
use anyhow::{Context, Result};
use keyring::Entry;
use std::env;
use std::sync::OnceLock;
use std::sync::Arc;
use tokio::sync::Mutex;

static CONFIG_CACHE: OnceLock<Arc<Mutex<Option<crate::config::Config>>>> = OnceLock::new();

/// 🔑 Henter en sikker verdi fra enten miljøvariabler eller `keyring`
pub async fn get_secure_value(
    env_key: &str,
    keyring_service: &str,
    keyring_user: &str,
) -> Result<String> {
    // 🎯 1️⃣ Sjekk om verdien finnes som en miljøvariabel
    if let Ok(value) = env::var(env_key) {
        return Ok(value);
    }

    // 🔐 2️⃣ Hvis ikke, prøv å hente verdien fra `keyring`
    let entry = Entry::new(keyring_service, keyring_user).context("Failed to access keyring")?;
    match entry.get_password() {
        Ok(password) => Ok(password),
        Err(_) => anyhow::bail!(
            "❌ Required secret not found! Set `{}` as an environment variable or store it in keyring.",
            env_key
        ),
    }
}

pub fn get_config_path() -> Option<String> {
    Some(
        dirs::home_dir()
            .expect("Failed to find home directory")
            .join(".config")
            .join("sdrive")
            .to_string_lossy()
            .to_string(),
    )
}

/// 🔑 Henter en verdi fra miljøvariabler, config.toml eller keyring
pub async fn get_value_from_env_or_config(
    env_key: &str,
    config_key: &str,
    keyring_service: Option<&str>,
) -> Result<String> {
    // 🎯 1️⃣ Sjekk miljøvariabelen
    if let Ok(value) = env::var(env_key) {
        return Ok(value);
    }

    // 📄 2️⃣ Hvis ikke, prøv å lese fra `config.toml`
    let config_path = get_config_path().expect("Failed to get config path");
    
    // Initialize or get the config cache
    let cache = CONFIG_CACHE.get_or_init(|| Arc::new(Mutex::new(None)));
    let mut cache_lock = cache.lock().await;
    
    // If config is not cached, read it
    if cache_lock.is_none() {
        let config = read_config(Some(config_path.clone())).await?;
        *cache_lock = Some(config);
    }

    // Get the value from cached config
    let config = cache_lock.as_ref().expect("Config should be cached");
    let value = match config_key {
        "api_key" => config.api_key.clone(),
        "user_guid" => config.user_guid.clone(),
        "encryption_key" => config.encryption_key.clone(),
        _ => String::new(),
    };

    if !value.is_empty() {
        return Ok(value);
    }

    // 🔐 3️⃣ Hvis fortsatt ikke funnet, prøv å hente fra keyring (hvis relevant)
    if let Some(service) = keyring_service {
        let entry = Entry::new(service, config_key).context("Failed to access keyring")?;
        if let Ok(password) = entry.get_password() {
            return Ok(password);
        }
    }

    // ❌ 4️⃣ Hvis vi kommer hit, mangler verdien fullstendig
    anyhow::bail!(
        "❌ Missing required value: `{}`. Set it as an environment variable, in config.toml, or store it in keyring.",
        env_key
    );
}
