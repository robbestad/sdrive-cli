use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};

pub fn create_sha256_fingerprint(file_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = BufReader::new(File::open(&file_path)?);
    let mut hasher = Sha256::new();

    let mut buffer = [0; 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    let fingerprint = format!("{:x}", hash);
    Ok(fingerprint)
}

/*
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file_path>", args[0]);
        return;
    }

    let file_path = &args[1];
    match create_sha256_fingerprint(file_path) {
        Ok(fingerprint) => println!("SHA-256 fingerprint: {}", fingerprint),
        Err(e) => eprintln!("Error generating fingerprint: {}", e),
    }
}
*/
