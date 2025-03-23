use aes_gcm::aead::{Aead, KeyInit};
use std::io;
use std::io::Write;
use std::fs;
use std::path::Path;
use aes_gcm::{Aes256Gcm, Nonce};
use keyring::Entry;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rand::RngCore;
use anyhow::Result;
use serde::de::DeserializeOwned;
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);
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

pub fn retrieve_key() -> Result<[u8; 32]> {
    let entry = Entry::new("sdrive", "master_key")?;
    let key_string = entry.get_password()?;
    println!("Retrieved master key (base64): {}", key_string);
    let decoded = STANDARD.decode(&key_string)?;
    if decoded.len() != 32 {
        return Err(anyhow::anyhow!("Invalid key length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

pub fn export_key() -> Result<String> {
    let key = retrieve_key()?;
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
    rand::rng().fill_bytes(&mut nonce);
    let nonce_obj = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(nonce_obj, plaintext)?;
    Ok((ciphertext, nonce))
}

pub fn encrypt_file(file_path: &Path) -> Result<(Vec<u8>, [u8; 32])> {
    let plaintext = fs::read(file_path)?;
    let master_key = retrieve_key()?;
    
    let per_file_key = generate_key();
    let (ciphertext, nonce) = encrypt_data(&per_file_key, &plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
    
    let cipher = Aes256Gcm::new_from_slice(&master_key).expect("Valid key size");
    let mut key_nonce = [0u8; 12];
    rand::rng().fill_bytes(&mut key_nonce);
    let key_nonce_obj = Nonce::from_slice(&key_nonce);
    let encrypted_key = cipher.encrypt(key_nonce_obj, per_file_key.as_ref()) // Endret til as_ref()
        .map_err(|e| anyhow::anyhow!("Failed to encrypt per-file key: {:?}", e))?;
    
    let mut encrypted_content = Vec::with_capacity(encrypted_key.len() + 12 + 12 + ciphertext.len());
    encrypted_content.extend_from_slice(&encrypted_key);
    encrypted_content.extend_from_slice(&key_nonce);
    encrypted_content.extend_from_slice(&nonce);
    encrypted_content.extend_from_slice(&ciphertext);
    
    Ok((encrypted_content, per_file_key))
}

pub fn decrypt_data(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8; 12]) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("Valid key size");
    let nonce_obj = Nonce::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce_obj, ciphertext)?;
    Ok(plaintext)
}

pub enum DecryptedData<T> {
    Raw(Vec<u8>),
    Structured(T),
}

pub fn decrypt_file<T: DeserializeOwned + 'static>(
    encrypted_file_path: &Path,
    output_file_path: Option<&Path>,
) -> Result<DecryptedData<T>> {
    let encrypted_data = fs::read(encrypted_file_path)?;
    
    if encrypted_data.len() < 56 {
        return Err(anyhow::anyhow!("Encrypted file too short to contain key and nonce"));
    }
    
    let (encrypted_key, rest) = encrypted_data.split_at(32);
    let (key_nonce_bytes, rest) = rest.split_at(12);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    
    let mut key_nonce = [0u8; 12];
    key_nonce.copy_from_slice(key_nonce_bytes);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);
    
    let master_key = retrieve_key()?;
    let cipher = Aes256Gcm::new_from_slice(&master_key).expect("Valid key size");
    let per_file_key = cipher.decrypt(Nonce::from_slice(&key_nonce), encrypted_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt per-file key: {:?}", e))?;
    
    if per_file_key.len() != 32 {
        return Err(anyhow::anyhow!("Decrypted per-file key has invalid length"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&per_file_key);
    
    let plaintext = decrypt_data(&key, ciphertext, &nonce)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
    
    if let Some(path) = output_file_path {
        fs::write(path, &plaintext)?;
        println!("File decrypted and saved to: {}", path.display());
    }
    
    if std::any::TypeId::of::<T>() == std::any::TypeId::of::<Vec<u8>>() {
        Ok(DecryptedData::Raw(plaintext))
    } else {
        let deserialized = serde_json::from_slice(&plaintext)
            .map_err(|e| anyhow::anyhow!("Deserialization failed: {}", e))?;
        Ok(DecryptedData::Structured(deserialized))
    }
}

pub fn export_per_file_key(encrypted_file_path: &Path) -> Result<String> {
    let encrypted_data = fs::read(encrypted_file_path)?;
    
    if encrypted_data.len() < 56 {
        return Err(anyhow::anyhow!("Encrypted file too short to contain key and nonce"));
    }
    
    let (encrypted_key, rest) = encrypted_data.split_at(32);
    let (key_nonce_bytes, _) = rest.split_at(12);
    
    let mut key_nonce = [0u8; 12];
    key_nonce.copy_from_slice(key_nonce_bytes);
    
    let master_key = retrieve_key()?;
    let cipher = Aes256Gcm::new_from_slice(&master_key).expect("Valid key size");
    let per_file_key = cipher.decrypt(Nonce::from_slice(&key_nonce), encrypted_key)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt per-file key: {:?}", e))?;
    
    Ok(STANDARD.encode(per_file_key))
}

pub fn decrypt_file_with_key<T: DeserializeOwned + 'static>(
    encrypted_file_path: &Path,
    output_file_path: Option<&Path>,
    per_file_key_b64: &str,
) -> Result<DecryptedData<T>> {
    let encrypted_data = fs::read(encrypted_file_path)?;
    
    if encrypted_data.len() < 56 {
        return Err(anyhow::anyhow!("Encrypted file too short to contain key and nonce"));
    }
    
    let (_encrypted_key, rest) = encrypted_data.split_at(32);
    let (_key_nonce_bytes, rest) = rest.split_at(12);
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
        println!("File decrypted and saved to: {}", path.display());
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

#[cfg(test)]
mod tests {
    use super::*;
    use keyring::Entry;

    #[test]
    fn test_generate_store_retrieve_key() {
        let test_service = "sdrive-test";
        let test_username = "encryption_key_test";
        let entry = Entry::new(test_service, test_username).expect("Could create test entry");
        let _ = entry.set_password("");
        let new_key = generate_key();
        let key_string = STANDARD.encode(new_key);
        entry
            .set_password(&key_string)
            .expect("Could store test key");
        let retrieved_key_string = entry.get_password().expect("Could retrieve test key");
        let decoded = STANDARD
            .decode(&retrieved_key_string)
            .expect("Could decode test key");
        let mut retrieved_key = [0u8; 32];
        retrieved_key.copy_from_slice(&decoded[..32]);
        assert_eq!(new_key, retrieved_key);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = generate_key();
        let plaintext = b"Test data to encrypt";
        let (ciphertext, nonce) = encrypt_data(&key, plaintext).expect("Encryption failed");
        let decrypted = decrypt_data(&key, &ciphertext, &nonce).expect("Decryption failed");
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_structured_data() {
        let key = generate_key();
        store_key(&key).expect("Failed to store key");
        let data = FileData {
            name: "test.txt".to_string(),
            content: vec![1, 2, 3, 4],
            metadata: Some("example".to_string()),
        };
        let serialized = serde_json::to_vec(&data).unwrap();
        fs::write("test.plain", &serialized).unwrap();
        let encrypted_content = encrypt_file(Path::new("test.plain")).expect("Encryption failed");
        fs::write("test.enc", &encrypted_content).unwrap();

        let decrypted: DecryptedData<FileData> =
            decrypt_file(Path::new("test.enc"), None).expect("Decryption failed");
        match decrypted {
            DecryptedData::Structured(file_data) => {
                assert_eq!(file_data.name, data.name);
                assert_eq!(file_data.content, data.content);
                assert_eq!(file_data.metadata, data.metadata);
            }
            DecryptedData::Raw(_) => panic!("Expected structured data"),
        }
        fs::remove_file("test.plain").unwrap();
        fs::remove_file("test.enc").unwrap();
    }
}
