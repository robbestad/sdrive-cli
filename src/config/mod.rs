use crate::encryption;
use serde::{Deserialize, Serialize};

use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use tokio::fs as tokio_fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(default = "default_api_key")]
    pub api_key: String,

    #[serde(default = "default_user_guid")]
    pub user_guid: String,

    #[serde(default = "default_sync_dir")]
    pub sync_dir: String,

    #[serde(default = "default_encryption_key")]
    pub encryption_key: String,

    #[serde(default = "default_port")]
    pub port: u16,
}

// Hjelpefunksjoner som henter verdier fra miljøvariabler
fn default_api_key() -> String {
    std::env::var("SDRIVE_API_KEY").unwrap_or_default()
}

fn default_user_guid() -> String {
    std::env::var("SDRIVE_USER_GUID").unwrap_or_default()
}

fn default_sync_dir() -> String {
    std::env::var("SDRIVE_SYNC_DIR").unwrap_or_else(|_| "/data/sdrive".to_string())
}

fn default_encryption_key() -> String {
    std::env::var("SDRIVE_ENCRYPTION_KEY").unwrap_or_default()
}

fn default_port() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8081)
}

// Implementerer Default for å gi fornuftige standardverdier
impl Default for Config {
    fn default() -> Self {
        Self {
            api_key: default_api_key(),
            user_guid: default_user_guid(),
            sync_dir: default_sync_dir(),
            encryption_key: default_encryption_key(),
            port: default_port(),
        }
    }
}

pub async fn generate_and_save_key(_config_path_option: Option<String>) -> io::Result<()> {
    // Generer en ny 32-bytes krypteringsnøkkel
    let key = encryption::generate_key();

    // Lagre nøkkelen i keyring (det sikre systemlagret)
    encryption::store_key(&key).expect("Could not store key in keyring");

    println!("Encryption key generated and stored in system's secure key storage (keyring).");

    Ok(())
}

async fn prompt_for_input_or_default(
    prompt_message: &str,
    default_value: Option<String>,
) -> io::Result<String> {
    print!(
        "{} ({}): ",
        prompt_message,
        default_value.as_deref().unwrap_or("Not Set")
    );
    io::stdout().flush()?; // Make sure the prompt is displayed immediately.

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    // If the user inputs something, use it; otherwise, fall back to the default value
    Ok(if !input.is_empty() {
        input.to_owned()
    } else {
        default_value.unwrap_or_default()
    })
}

async fn set_value(
    value_option: Option<String>,
    default_value: Option<String>,
    text: &str,
) -> io::Result<String> {
    match value_option {
        Some(dir) => Ok(dir), // If there's an option, use it.
        None => prompt_for_input_or_default(text, default_value).await,
    }
}

pub async fn prompt_and_save_config(
    config_path_option: Option<std::string::String>,
    sync_dir_option: Option<std::string::String>,
    user_guid_option: Option<std::string::String>,
    api_key_option: Option<std::string::String>,
) -> io::Result<()> {
    let mut config_path = config_path_option.map(PathBuf::from).unwrap_or_else(|| {
        dirs::home_dir()
            .expect("Failed to find home directory")
            .join(".config")
            .join("sdrive")
    });

    // Ensure the config directory exists
    if !config_path.exists() {
        fs::create_dir_all(&config_path)?;
    }
    // The path to the configuration file
    let config_file_path = config_path.join("config.toml");

    // Attempt to read the configuration file if it exists
    let config = if config_file_path.exists() {
        let contents = fs::read_to_string(&config_file_path)?;
        toml::from_str::<Config>(&contents).unwrap_or_else(|_| Config {
            sync_dir: String::new(),
            user_guid: String::new(),
            api_key: String::new(),
            encryption_key: String::new(),
            port: 0,
        })
    } else {
        Config {
            sync_dir: String::new(),
            user_guid: String::new(),
            api_key: String::new(),
            encryption_key: String::new(),
            port: 0,
        }
    };
    let sync_dir = set_value(
        sync_dir_option,
        Some(config.sync_dir),
        "Please enter the location of your sync path",
    )
    .await?;
    let api_key = set_value(
        api_key_option,
        Some(config.api_key),
        "Please enter your API key",
    )
    .await?;
    let user_guid = set_value(
        user_guid_option,
        Some(config.user_guid),
        "Please enter your GUID or press Enter to ignore",
    )
    .await?;

    // Determine the path to the configuration file
    fs::create_dir_all(&config_path)?; // Create .config directory if it doesn't exist
    config_path.push("config.toml");

    // Write the API key to the configuration file
    let config_content = format!(
        "api_key=\"{}\"\nuser_guid=\"{}\"\nsync_dir=\"{}\"\n",
        api_key, user_guid, sync_dir
    );
    fs::write(config_path, config_content)?;

    println!("Config saved successfully.");

    Ok(())
}

pub async fn read_config(config_path_option: Option<String>) -> Result<Config, io::Error> {
    let config_file_path = match config_path_option {
        Some(path_str) => {
            let path = PathBuf::from(path_str);
            if path.is_dir() {
                path.join("config.toml")
            } else if path.extension().map_or(false, |ext| ext == "toml") {
                path
            } else {
                path.join("config.toml")
            }
        }
        None => dirs::home_dir()
            .expect("Failed to find home directory")
            .join(".config")
            .join("sdrive")
            .join("config.toml"),
    };

    if config_file_path.exists() {
        println!("📖 Reading config from file: {:?}", config_file_path);
        let contents = tokio_fs::read_to_string(&config_file_path).await?;
        let mut config: Config =
            toml::from_str(&contents).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Sjekk om noen verdier mangler i filen og hent fra env
        if config.api_key.is_empty() {
            config.api_key = default_api_key();
        }
        if config.user_guid.is_empty() {
            config.user_guid = default_user_guid();
        }
        if config.sync_dir.is_empty() {
            config.sync_dir = default_sync_dir();
        }
        if config.encryption_key.is_empty() {
            config.encryption_key = default_encryption_key();
        }

        Ok(config)
    } else {
        println!(
            "⚠️ Config file not found at {:?}, using environment variables and defaults.",
            config_file_path
        );
        Ok(Config::default())
    }
}
