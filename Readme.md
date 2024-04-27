# Autho: Open Source Authentication and Password Management Tool

Autho is an open-source, self-hosted alternative to services like Authy, providing One-Time Password (OTP) generation and password management functionalities. With Autho, users can securely manage their authentication tokens and passwords while maintaining full control over their data.

## Features

- **OTP Generation**: Autho allows users to generate One-Time Passwords (OTPs) for two-factor authentication (2FA) using industry-standard algorithms.
- **Password Management**: Autho provides a secure vault for users to store and manage their passwords, ensuring easy access and strong encryption.

- **Self-Hosted**: Autho can be self-hosted, giving users complete control over their data and eliminating reliance on third-party services.

- **Open Source**: Autho is open-source software, allowing users to inspect, modify, and contribute to its codebase, ensuring transparency and security.

## Installation

To install Autho globally, use npm:

```sh
npm install -g autho
```

## Getting Started

1. **Setting Up Autho**: After installation, run the `autho` command to set up Autho for the first time. Follow the on-screen instructions to configure your master password and other settings.

2. **Generating OTPs**: Use Autho to generate OTPs for your accounts by providing the associated account name or label. Autho will generate a time-based OTP using a secure algorithm.

3. **Managing Passwords**: Autho provides a secure vault for storing and managing your passwords. You can add, view, update, and delete passwords using the CLI interface.

4. **Secure files**: Autho offers a reliable method for encrypting and decrypting files, ensuring their security and integrity.

5. **Self-Hosting**: If you prefer self-hosting, deploy Autho on your own server by following the instructions provided in the documentation. (TBD)

## Security Considerations

- **Encryption**: Autho employs strong encryption algorithms to protect user data, ensuring that passwords and OTPs are securely stored.

- **Master Password**: Users are required to set a master password during setup, which is used to encrypt and decrypt their data. Choose a strong and unique master password to enhance security.

- **Self-Hosting**: By self-hosting Autho, users maintain control over their data and reduce reliance on external services, minimizing the risk of data breaches.

- **Regular Updates**: Keep Autho and its dependencies up to date to ensure that security vulnerabilities are addressed promptly.

## Usage

```bash
autho [options] [command]
```

### Options:

- `--version`: Output the version number
- `-p, --password <password>`: Master password
- `-ph, --passwordHash <passwordHash>`: Master password hash
- `-n, --name <name>`: Collection name
- `--dataFolder <folderPath>`: Folder path to store secrets db
- `-h, --help`: Display help for command

### Commands:

#### 0. `prompt`

The main terminal ui, recommended most ot the time.

```bash
autho
```

#### 1. `import`

Import secrets from a backup file.

```bash
autho import --filePath <filePath>
```

#### 2. `secret`

Perform secret operations like creating, listing, reading, and deleting secrets.

```bash
autho secret [options]
```

Options:
- `--action <action>`: Secret action (create/list/read/delete)
- `--id <id>`: Secret id
- `--decrypt`: Decrypt secret

#### 3. `file`

Encrypt/Decrypt a file.

```bash
autho file [options]
```

Options:
- `-f, --filePath <filePath>`: File path
- `-en, --encrypt`: Encrypt file
- `-de, --decrypt`: Decrypt file
- `--override`: Override original file

#### 4. `files`

Encrypt/Decrypt files in a folder.

```bash
autho files [options]
```

Options:
- `--input <inputPath>`: Folder path
- `--output <outputPath>`: Folder path
- `-en, --encrypt`: Encrypt folder
- `-de, --decrypt`: Decrypt folder

## Examples

1. Import secrets from a backup file:
```bash
autho import --filePath backup.json
```

2. Create a new secret:
```bash
autho secret --action create
```

3. Read a secret:
```bash
autho secret --action read --id <secretId> --decrypt
```

4. Encrypt a file:
```bash
autho file --filePath secret.txt --encrypt
```

5. Decrypt a file:
```bash
autho file --filePath secret.txt.autho --decrypt
```

6. Encrypt files in a folder:
```bash
autho files --input /path/to/folder --encrypt
```

7. Decrypt files in a folder:
```bash
autho files --input /path/to/folder.autho --decrypt
```

## Contributing

Autho is an open-source project, and contributions are welcome! Feel free to report issues, suggest features, or submit pull requests on the project's GitHub repository.

## License

Autho is licensed under the [MIT License](LICENSE), allowing for unrestricted use, modification, and distribution.

## Support

For support or inquiries, please open an issue for assistance.

## Acknowledgments

Autho is built upon various open-source libraries and technologies. We extend our gratitude to the developers and contributors of these projects.
