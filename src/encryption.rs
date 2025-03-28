use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use hex;
use keyring::Entry;
use rand::rng;
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde_json;
use std::fs;
use std::path::Path;

use crate::secret::get_value_from_env_or_config;

pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rng().fill_bytes(&mut key);
    key
}

pub fn store_key(key: &[u8; 32]) -> Result<()> {
    let entry = Entry::new("sdrive", "master_key")?;
    let key_string = STANDARD.encode(key);
    println!("Generated master key (base64): {}", key_string);
    entry.set_password(&key_string)?;
    let stored_key = entry.get_password()?;
    println!("Verified stored master key (base64): {}", stored_key);
    Ok(())
}

pub async fn retrieve_key() -> Result<[u8; 32]> {
    let key_string = get_value_from_env_or_config("SDRIVE_ENCRYPTION_KEY", "encryption_key", Some("sdrive")).await?;
    
    let decoded = STANDARD.decode(&key_string)?;
    if decoded.len() != 32 {
        return Err(anyhow::anyhow!("Invalid encryption key length"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

pub async fn export_key() -> Result<String> {
    let key = retrieve_key().await?;
    let key_string = STANDARD.encode(key);
    Ok(key_string)
}

pub fn import_key(key_string: &str) -> Result<()> {
    let decoded = STANDARD.decode(key_string)?;
    if decoded.len() != 32 {
        return Err(anyhow::anyhow!("Invalid key length; must be 32 bytes"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    store_key(&key)?;
    Ok(())
}

fn encrypt_data(key: &[u8; 32], plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12]), aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key size");
    let mut nonce = [0u8; 12];
    rng().fill_bytes(&mut nonce);
    let nonce_obj = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce_obj, plaintext)?;
    Ok((ciphertext, nonce))
}
pub async fn encrypt_file(file_path: &Path) -> Result<(Vec<u8>, [u8; 32])> {
    let plaintext = fs::read(file_path)?;
    tracing::debug!("⚙️ Plaintext size: {} bytes", plaintext.len());
    let master_key = retrieve_key().await?;

    let per_file_key = generate_key();
    let (ciphertext, nonce) = encrypt_data(&per_file_key, &plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    tracing::debug!("⚙️ Ciphertext size: {} bytes", ciphertext.len());

    let cipher = Aes256Gcm::new_from_slice(&master_key).expect("Valid key size");
    let mut key_nonce = [0u8; 12];
    rng().fill_bytes(&mut key_nonce);
    let key_nonce_obj = Nonce::from_slice(&key_nonce);
    let encrypted_key = cipher
        .encrypt(key_nonce_obj, per_file_key.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt per-file key: {:?}", e))?;

    let mut encrypted_content =
        Vec::with_capacity(encrypted_key.len() + 12 + 12 + ciphertext.len());
    encrypted_content.extend_from_slice(&encrypted_key);
    encrypted_content.extend_from_slice(&key_nonce);
    encrypted_content.extend_from_slice(&nonce);
    encrypted_content.extend_from_slice(&ciphertext);
    tracing::trace!("⚙️ Encrypted content size: {}", encrypted_content.len());

    if encrypted_content.len() != (encrypted_key.len() + 12 + 12 + ciphertext.len()) {
        return Err(anyhow::anyhow!(
            "Encrypted content size mismatch: expected {}, got {}",
            encrypted_key.len() + 12 + 12 + ciphertext.len(),
            encrypted_content.len()
        ));
    }

    Ok((encrypted_content, per_file_key))
}
pub fn decrypt_data(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key size");
    let nonce_obj = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce_obj, ciphertext)?;
    Ok(plaintext)
}

pub enum DecryptedData<T> {
    Raw(Vec<u8>),
    Structured(T),
}

pub async fn decrypt_file<T: DeserializeOwned + 'static>(
    encrypted_file_path: &Path,
    output_file_path: Option<&Path>
) -> Result<DecryptedData<T>> {
    let encrypted_data = fs::read(encrypted_file_path)?;
    tracing::trace!("Encrypted data size: {} bytes", encrypted_data.len());

    if encrypted_data.len() < 72 {
        return Err(anyhow::anyhow!(
            "Encrypted file too short to contain key and nonce"
        ));
    }

    let (encrypted_key, rest) = encrypted_data.split_at(48);
    tracing::trace!("Encrypted key (hex): {}", hex::encode(encrypted_key));

    let (key_nonce_bytes, rest) = rest.split_at(12);
    tracing::trace!("Key nonce (hex): {}", hex::encode(key_nonce_bytes));
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    tracing::trace!("Nonce (hex): {}", hex::encode(nonce_bytes));
    tracing::trace!("Ciphertext (hex): {}", hex::encode(ciphertext));

    let mut key_nonce = [0u8; 12];
    key_nonce.copy_from_slice(key_nonce_bytes);
    tracing::trace!("Key nonce (hex): {}", hex::encode(key_nonce));
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);
    tracing::trace!("Nonce (hex): {}", hex::encode(nonce));

    let master_key = retrieve_key().await?;
    let cipher = Aes256Gcm::new_from_slice(&master_key).expect("Valid key size");
    tracing::trace!("Master key (hex): {}", hex::encode(&master_key));
    let per_file_key = cipher
        .decrypt(Nonce::from_slice(&key_nonce), encrypted_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt per-file key: {:?}", e))?;
    tracing::trace!(
        "Decrypted per-file key (hex): {}",
        hex::encode(&per_file_key)
    );

    if per_file_key.len() != 32 {
        return Err(anyhow::anyhow!("Decrypted per-file key has invalid length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&per_file_key);

    let plaintext = decrypt_data(&key, ciphertext, &nonce)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    if let Some(path) = output_file_path {
        fs::write(path, &plaintext)?;
        //println!("File decrypted and saved to: {}", path.display());
    }

    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<Vec<u8>>() {
        Ok(DecryptedData::Raw(plaintext))
    } else {
        let deserialized = serde_json::from_slice(&plaintext)
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?;
        Ok(DecryptedData::Structured(deserialized))
    }
}

pub async fn export_per_file_key(encrypted_file_path: &Path) -> Result<String> {
    let encrypted_data = fs::read(encrypted_file_path)?;

    if encrypted_data.len() < 72 {
        return Err(anyhow::anyhow!(
            "Encrypted file too short to contain key and nonce"
        ));
    }

    // Oppdatert her: bruk 48 bytes for encrypted_key
    let (encrypted_key, rest) = encrypted_data.split_at(48);
    let (key_nonce_bytes, _) = rest.split_at(12);

    let mut key_nonce = [0u8; 12];
    key_nonce.copy_from_slice(key_nonce_bytes);

    let master_key = retrieve_key().await?;
    let cipher = Aes256Gcm::new_from_slice(&master_key).expect("Valid key size");

    let per_file_key = cipher
        .decrypt(Nonce::from_slice(&key_nonce), encrypted_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt per-file key: {:?}", e))?;

    Ok(STANDARD.encode(per_file_key))
}

pub fn decrypt_file_with_key<T: DeserializeOwned + 'static>(
    encrypted_file_path: &Path,
    output_file_path: Option<&Path>,
    per_file_key_b64: &str,
) -> Result<DecryptedData<T>> {
    let encrypted_data = fs::read(encrypted_file_path)?;

    if encrypted_data.len() < 72 {
        // 48 (encrypted_key) + 12 (key_nonce) + 12 (nonce)
        return Err(anyhow::anyhow!(
            "Encrypted file too short to contain key and nonce"
        ));
    }

    // Hopp over encrypted_key (48) + key_nonce (12) = 60 bytes
    let rest = &encrypted_data[60..];
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    let per_file_key = STANDARD.decode(per_file_key_b64)?;
    if per_file_key.len() != 32 {
        return Err(anyhow::anyhow!("Invalid per-file key length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&per_file_key);

    let plaintext = decrypt_data(&key, ciphertext, &nonce)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

    if let Some(path) = output_file_path {
        fs::write(path, &plaintext)?;
        //println!("File decrypted and saved to: {}", path.display());
    }

    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<Vec<u8>>() {
        Ok(DecryptedData::Raw(plaintext))
    } else {
        let deserialized = serde_json::from_slice(&plaintext)
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?;
        Ok(DecryptedData::Structured(deserialized))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
struct FileData {
    name: String,
    content: Vec<u8>,
    metadata: Option<String>,
}

// ... (testene beholdes som de er, men kan trenge justering for det nye formatet)
