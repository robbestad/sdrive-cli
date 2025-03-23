# SDRIVE CLI - Secure File Sharing with End-to-End Encryption

SDRIVE CLI is a command-line tool for secure file sharing with end-to-end encryption and per-file key sharing. The tool allows you to easily share files with others while maintaining full control over access.

## Installation

1. cargo install sdrive

## Commands

### Configuration

#### Create Configuration
```bash
sdrive config create
```
This will guide you through setting up:
- API key (available at https://sdrive.pro)
- User GUID
- RPC URL
- Sync directory
- Keypair path

#### Generate Encryption Key
```bash
sdrive config generate-key
```
Generates a secure encryption and decryption key in your keyring.

#### Export Key
```bash
sdrive config export-key
```
Exports the master encryption key in base64 format for sharing with others.

#### Import Key
```bash
sdrive config import-key <base64-key>
```
Imports a master encryption key from base64 format.

### File Operations

#### Upload File
```bash
sdrive upload <filepath>
```
Uploads a file to SDRIVE with end-to-end encryption. The file is automatically encrypted before upload.

#### Download File
```bash
sdrive download <url> [--output <filepath>] [--key <base64-key>]
```
Downloads and decrypts a file from SDRIVE. You can specify:
- `--output`: Where to save the decrypted file
- `--key`: A per-file key for decryption (optional)

Supports downloading from:
- cdn.sdrive.pro
- ipfs.sdrive.pro

#### Decrypt File
```bash
sdrive decrypt <filepath> [--output <filepath>]
```
Decrypts a locally stored file. You can specify:
- `--output`: Where to save the decrypted file

### Synchronization
```bash
sdrive sync
```
(Under development) Synchronizes files between local directories and SDRIVE.

## Security

- End-to-end encryption for all file sharing
- Support for per-file key sharing
- Secure storage of master key in system keyring
- Download URL validation

## Logging

You can control the log level using the `--log-level` flag:
```bash
sdrive --log-level debug <command>
```

## Troubleshooting

If you experience issues:
1. Verify that your API key is valid
2. Check that you have the correct configuration in `sdrive.toml`
3. Ensure the master key is properly installed in the keyring
4. Enable debug logging for more detailed information

## License

This project is licensed under the MIT License.

