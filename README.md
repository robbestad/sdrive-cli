# SDRIVE CLI - Secure File Sharing with End-to-End Encryption

SDRIVE CLI is a powerful command-line tool designed for secure file sharing with end-to-end encryption and per-file key sharing capabilities. Built with security and ease of use in mind, it allows you to share files with others while maintaining complete control over access and ensuring your data remains private and secure.

## Installation

1. Install using Cargo (Rust's package manager):
```bash
cargo install sdrive
```

## Commands

### Configuration

#### Create Configuration
```bash
sdrive config create
```
This interactive command will guide you through the initial setup process:
- API key: Your unique authentication key from https://sdrive.pro
- User GUID: Your personal identifier for the SDRIVE service

The configuration is stored securely in your local system and is required for all other operations.

#### Generate Encryption Key
```bash
sdrive config generate-key
```
This command creates a secure master encryption key that is stored in your system's keyring. This key is used for:
- Encrypting files before upload
- Decrypting files you download
- Managing access to your shared files

The key is never stored in plain text and is protected by your system's security mechanisms.

#### Export Key
```bash
sdrive config export-key
```
Exports your master encryption key in base64 format. This is useful for:
- Creating backups of your encryption key
- Transferring your key to another device
- Setting up multiple devices with the same access

⚠️ Store the exported key securely and never share it with unauthorized parties.

#### Import Key
```bash
sdrive config import-key <base64-key>
```
Imports a previously exported master encryption key from base64 format. This allows you to:
- Restore your key from a backup
- Set up a new device with your existing key
- Maintain consistent access across multiple devices

### File Operations

#### Upload File
```bash
sdrive upload <filepath>
```
Uploads a file to SDRIVE with multiple layers of security:
- Automatic end-to-end encryption before upload
- Server-side encryption at rest
- Optional per-file sharing key generation

When uploading, you'll receive a unique sharing key for the specific file. This key enables:
- Secure file sharing with anyone
- No need to share your master key
- Control over individual file access

#### Download File
```bash
sdrive download <url> [--output <filepath>] [--key <base64-key>]
```
Downloads and decrypts files from SDRIVE with flexible options:
- `--output`: Specify a custom location for the decrypted file
- `--key`: Use a per-file sharing key for decryption (optional)

Supports multiple download sources:
- cdn.sdrive.pro: Fast, CDN-based downloads
- ipfs.sdrive.pro: Decentralized IPFS-based downloads

#### Decrypt File
```bash
sdrive decrypt <filepath> [--output <filepath>]
```
Decrypts locally stored encrypted files using your keyring:
- Works with any file encrypted by SDRIVE
- Supports custom output locations
- Maintains security by using your stored master key

## Security Features

SDRIVE CLI implements multiple security measures to protect your data:
- End-to-end encryption: Files are encrypted before upload and remain encrypted in transit
- Per-file key sharing: Share individual files without exposing your master key
- Secure key storage: Master keys are stored in your system's keyring, not in plain text
- URL validation: Ensures downloads only from trusted SDRIVE domains
- No data retention: Files are automatically removed after the specified retention period

## Logging

Control the verbosity of logging output with the `--log-level` flag:
```bash
sdrive --log-level debug <command>
```
Available log levels:
- error: Only show critical errors
- warn: Show warnings and errors
- info: Show general information (default)
- debug: Show detailed debugging information
- trace: Show extremely detailed debugging information

## Troubleshooting

If you encounter any issues, follow these steps:
1. Verify your API key is valid and properly configured
2. Check your `sdrive.toml` configuration file for correct settings
3. Ensure your master key is properly installed in the keyring
4. Enable debug logging for detailed error information
5. Check your internet connection and firewall settings
6. Verify you have sufficient disk space for operations

## License

This project is licensed under the MIT License, allowing for:
- Commercial use
- Modification
- Distribution
- Private use

See the LICENSE file for full details.

