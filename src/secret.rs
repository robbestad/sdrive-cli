use keyring::Entry;
use std::env;
use anyhow::{Result, Context};
use crate::config::read_config;

/// 🔑 Henter en sikker verdi fra enten miljøvariabler eller `keyring`
pub async fn get_secure_value(env_key: &str, keyring_service: &str, keyring_user: &str) -> Result<String> {
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
pub async fn get_value_from_env_or_config(env_key: &str, config_key: &str, keyring_service: Option<&str>) -> Result<String> {
    // 🎯 1️⃣ Sjekk miljøvariabelen
    if let Ok(value) = env::var(env_key) {
        return Ok(value);
    }

    // 📄 2️⃣ Hvis ikke, prøv å lese fra `config.toml`
    let config_path = get_config_path().expect("Failed to get config path");
    let config = read_config(Some(config_path)).await?;
    if let Some(value) = match config_key {
        "api_key" => config.api_key,
        "user_guid" => config.user_guid,
        "encryption_key" => config.encryption_key,
        _ => None,
    } {
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
