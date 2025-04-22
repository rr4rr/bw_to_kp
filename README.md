# Complete Bitwarden to KeePass Backup Solution

A comprehensive utility for exporting Bitwarden vaults to KeePass format with support for all entry types, including attachments, passkeys, SSH keys, and more. Perfect for users looking for a complete export/backup solution from Bitwarden to KeePass.

## Features

- **Full Vault Export**: Transfers all items from Bitwarden to KeePass including logins, secure notes, credit cards, identities, SSH keys, and passkeys
- **Attachments Support**: Preserves all attachments with proper naming and binary data handling
- **Folder Structure**: Maintains your original folder organization
- **Passkey/WebAuthn Support**: Properly exports FIDO2 credentials in KeePassXC/Strongbox compatible format
- **Custom Fields**: Preserves all custom fields with appropriate protection for sensitive data
- **TOTP Support**: Exports Time-based One-Time Password secrets in formats compatible with KeePass plugins
- **Enhanced Security**: Option to create a keyfile for additional protection
- **Platform Independence**: Automatically detects and works on Windows, macOS, and Linux
- **Batch Processing**: Configurable batch sizes for more efficient processing of large vaults
- **Comprehensive Logging**: Detailed logging with configurable verbosity
- **Automatic CLI Installation**: Automatically downloads the Bitwarden CLI if not found in the current directory or system PATH

## Requirements

- Python 3.6 or higher
- `pykeepass` library (automatically prompts for installation if missing)
- Internet connection for downloading the Bitwarden CLI (if not already installed)

## Installation

1. Clone this repository or download the script files:
   ```
   git clone https://github.com/yourusername/bitwarden-to-keepass.git
   cd bitwarden-to-keepass
   ```

2. Install the required dependencies:
   ```
   pip install pykeepass
   ```

## Usage

Basic usage:
```
python bw_to_keepass_exporter.py
```

Recommended for first-time users to track the export process:
```
python bw_to_keepass_exporter.py --debug
```

With additional options:
```
python bw_to_keepass_exporter.py --output my_vault.kdbx --keyfile my_vault.key --debug
```

### Command Line Options

- `-o, --output`: Specify the output KeePass file path
- `-k, --keyfile`: Create and use a KeePass keyfile for additional security
- `-d, --debug`: Enable debug logging for more detailed information
- `-b, --batch-size`: Number of items to process in one batch (default: 100)
- `--bw-path`: Custom path to Bitwarden CLI executable (if already installed)

## How It Works

1. The script connects to your Bitwarden account using the official Bitwarden CLI
   - If the CLI is not found, it automatically downloads the appropriate version for your platform
2. It syncs your vault to ensure all data is up-to-date
3. Folder structure is processed and recreated in KeePass
4. All items are exported with their properties, custom fields, and attachments
5. Special handling is applied for passkeys, SSH keys, and other specialized entry types
6. The KeePass database is saved with your chosen password (and optional keyfile)

## Supported Item Types

- **Logins**: Username, password, URLs, TOTP secrets, passkeys
- **Secure Notes**: All content with proper formatting
- **Credit Cards**: Card details with appropriate field protection
- **Identities**: Personal information with sensitive fields protected
- **SSH Keys**: Private and public keys with proper formatting and protection
- **Passkeys/WebAuthn**: FIDO2 credentials in standard KeePassXC format

## Security Considerations

- Your master password is never stored persistently
- The Bitwarden session is terminated after export
- Temporary cache files are securely removed after use
- Sensitive fields are properly protected in the KeePass database
- Option to use a keyfile for additional security

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Bitwarden for their excellent password manager and CLI
- The KeePass project for their secure password database format
- pykeepass developers for the Python library to work with KeePass files
