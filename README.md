# Installation
```
git clone https://github.com/Scroll07/password_manager.git

cd password_manager
./realise.sh

pas api register
```
Dependencies that will be installed if you don't have them:
- gnome-keyring
- pipx
- uv

# Password Manager CLI

A client-side CLI password manager with local vault encryption and remote backup support via REST API.  
The vault is encrypted with a master password and stored locally. Optional cloud backups are uploaded to a remote API server.

## Features

- Local vault encrypted with a master password
- Generate, store, search, edit, delete password entries
- Copy password to clipboard
- Export/import vault to/from a file
- Remote backup: upload, download, rename, delete, pin backups on the API server
- Password strength checker (common patterns, length, character variety)
- Credentials stored securely via system keyring
- CLI built with Typer — bash auto-completion out of the box

## Tech Stack

- **Python** — Typer, Cryptography (Fernet/AES), Keyring, Requests
- **System keyring** — GNOME Keyring (stores master password session)
- **Remote API** — FastAPI backend (separate repo)
- **pytest** — test suite

## Project Structure

```text
src/
└── pas_app/
    ├── adapters/         # Console input/output (prompts, console helpers)
    ├── cli/              # Typer CLI app commands
    ├── api_commands/     # pas api register/login/upload/backups/...
    ├── config_commands/  # pas config user/url/token/session
    ├── pas_commands/     # pas add/list/get/copy/edit/del/find/export/import/gen
    ├── user_commands/    # pas user delete/change-master
    ├── core/             # API client, crypto utils, keyring wrapper
    ├── schemas/          # Pydantic schemas (passwords, API responses, JWT)
    ├── services/         # Vault logic, password strength checker, file utils
    ├── config.py         # Config loader (toml + keyring)
    ├── exceptions.py     # Custom exceptions
    └── main.py           # Entry point

tests/                # pytest test suite
data/                 # Common password lists for strength checker
scripts/              # realise.sh and helpers
```


**BASE COMMANDS**
| Command    | Description                          | Example                      |
| ---------- | ------------------------------------ | ---------------------------- |
| pas add    | Add a new entry to the local vault   | pas add github -u user --gen |
| pas list   | Show all saved entries               | pas list                     |
| pas get    | Show an entry by label               | pas get github               |
| pas copy   | Copy a password by entry number      | pas copy 2                   |
| pas edit   | Edit an existing entry               | pas edit 1 -p newpass        |
| pas del    | Delete an entry from the local vault  | pas del github               |
| pas find   | Search entries in the vault          | pas find @gmail              |
| pas export | Export vault data to a file          | pas export backup.json       |
| pas import | Import vault data from a file        | pas import backup.json       |
| pas gen    | Generate a password                  | pas gen -l 32                |

**API COMMANDS**
| Command                 | Description                                      | Example                 |
| ----------------------- | ------------------------------------------------ | ----------------------- |
| pas api register        | Register a new account for remote backup storage | pas api register        |
| pas api login           | Authenticate and save API session locally        | pas api login           |
| pas api upload          | Upload the current local vault as a backup       | pas api upload          |
| pas api backups         | Interactively manage backups on the server       | pas api backups         |
│ pas api stats           │ Backup statistics for the user's account.        │ pas api stats           │
| pas api change-password | Change the current account password              | pas api change-password |

**USER COMMANDS**
| Command                 | Description                | Example                |
| ------------------------| -------------------------- | ---------------------- |
| pas user delete         | Delete a local user        | pas user delete        |
| pas user change-master  | Change the master password | pas user change-master |

**CONFIG COMMANDS**
| Command                  | Description                     | Example                  |
| ------------------------ | ------------------------------- | ------------------------ |
| pas config user          | Set the default local user      | pas config user          |
| pas config url           | View or change the API base URL | pas config url           |
| pas config token         | View or change the bot token    | pas config token         |
| pas config reset-session | Reset the current local session | pas config reset-session |
