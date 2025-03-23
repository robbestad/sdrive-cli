use crate::encryption;
use serde::Deserialize;
use serde::Serialize;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    pub rpc_url: Option<String>,
    pub sync_dir: Option<String>,
    pub user_guid: Option<String>,
    pub api_key: Option<String>,
    pub keypair_path: Option<String>,
    pub encryption_key: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            rpc_url: None,
            sync_dir: None,
            user_guid: None,
            api_key: None,
            keypair_path: None,
            encryption_key: None,
        }
    }
}

pub async fn generate_and_save_key(_config_path_option: Option<String>) -> io::Result<()> {
    // Generer en ny 32-bytes krypteringsnøkkel
    let key = encryption::generate_key();

    // Lagre nøkkelen i keyring (det sikre systemlagret)
    encryption::store_key(&key).expect("Kunne ikke lagre nøkkelen i keyring");

    println!("Krypteringsnøkkel generert og lagret i systemets sikre nøkkellager (keyring).");

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
    rpc_url_option: Option<std::string::String>,
    sync_dir_option: Option<std::string::String>,
    user_guid_option: Option<std::string::String>,
    api_key_option: Option<std::string::String>,
    keypair_path_option: Option<std::string::String>,
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
            rpc_url: None,
            sync_dir: None,
            user_guid: None,
            api_key: None,
            keypair_path: None,
            encryption_key: None,
        })
    } else {
        Config {
            rpc_url: None,
            sync_dir: None,
            user_guid: None,
            api_key: None,
            keypair_path: None,
            encryption_key: None,
        }
    };
    let sync_dir = set_value(
        sync_dir_option,
        config.sync_dir,
        "Please enter the location of your sync path",
    )
    .await?;
    let api_key = set_value(api_key_option, config.api_key, "Please enter your API key").await?;
    let user_guid = set_value(
        user_guid_option,
        config.user_guid,
        "Please enter your GUID or press Enter to ignore",
    )
    .await?;
    let rpc_url = set_value(
        rpc_url_option,
        config.rpc_url,
        "Please enter your RPC URL or press Enter to ignore",
    )
    .await?;
    let keypair_path = set_value(
        keypair_path_option,
        config.keypair_path,
        "Please enter the location of your keypair or press Enter to ignore",
    )
    .await?;

    // Determine the path to the configuration file
    fs::create_dir_all(&config_path)?; // Create .config directory if it doesn't exist
    config_path.push("config.toml");

    // Write the API key to the configuration file
    let config_content = format!(
        "api_key=\"{}\"\nuser_guid=\"{}\"\nsync_dir=\"{}\"\nrpc_url=\"{}\"\nkeypair_path=\"{}\"\n",
        api_key, user_guid, sync_dir, rpc_url, keypair_path
    );
    fs::write(config_path, config_content)?;

    println!("Config saved successfully.");

    Ok(())
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

    // At this point, config_file_path is correctly determined
    if config_file_path.exists() {
        let contents = fs::read_to_string(&config_file_path)?;
        toml::from_str::<Config>(&contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    } else {
        // Return a default Config if the file doesn't exist
        Ok(Config::default())
    }
}
