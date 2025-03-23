use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

/// Lagrer nøkkelen i base64-format.
pub fn save_key(key: &[u8; 32], path: &PathBuf) -> io::Result<()> {
    let encoded = base64::encode(key);
    fs::write(path, encoded)
}

/// Leser nøkkelen fra filen og konverterer tilbake til en 32-bytes array.
pub fn load_key(path: &PathBuf) -> io::Result<[u8; 32]> {
    let encoded = fs::read_to_string(path)?;
    let decoded = base64::decode(encoded.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[0..32]);
    Ok(key)
}
