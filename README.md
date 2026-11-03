# Password Manager CLI

A secure, client-side CLI password manager featuring encrypted local vaults, multi-user/multi-vault support, and cloud backup synchronization via a FastAPI REST service.

Vaults are encrypted locally using a master key derived via KEK/DEK architecture and AES/Fernet encryption. Authentication tokens and active vault sessions are stored securely in the system keyring.

---

## Installation

```bash
git clone https://github.com/Scroll07/password_manager.git
cd password_manager
chmod +x ./realise.sh
./realise.sh

# Register your remote account or start offline
pas user register

```

### Dependencies

Installed automatically via `realise.sh` if missing:

* `gnome-keyring` (system credential storage)
* `pipx`
* `uv`

---

## Features

* **Local-First Security:** Zero-knowledge client-side encryption with separate Key Encryption Key (KEK) and Data Encryption Key (DEK).
* **Multi-User & Multi-Vault Management:** Maintain multiple isolated user accounts and switch between independent vaults (`work`, `personal`, etc.).
* **Cloud Synchronization:**
* `fetch`: Non-destructive dry-run inspection of local vs. server versions.
* `push` & `pull`: Version-aware uploads and downloads with conflict detection (`--force`, `--new`, `--overwrite`).
* `sync`: Automatic bidirectional sync for all tracked vaults.


* **Interactive Deletion Wizard:** Safe vault deletion allowing targets: local-only, server-only, or complete removal.
* **Interactive Credential Wizard:** Step-by-step interactive entry mode for `pas add` with automatic password generation.
* **Session Management:** Temporary master password and JWT caching in the system keyring.

---

## Tech Stack

* **CLI Framework:** [Typer](https://typer.tiangolo.com/) (rich formatting, shell auto-completion)
* **Cryptography:** [cryptography](https://cryptography.io/) (Fernet, symmetric key derivation)
* **Data Validation & Serialization:** [Pydantic v2](https://docs.pydantic.dev/)
* **System Keyring:** [keyring](https://github.com/jaraco/keyring) (GNOME Keyring integration)
* **HTTP Client:** HTTP client communicating with a remote FastAPI server

---

## Project Structure

```text
├── src/
│   └── pas_app/
│       ├── adapters/         # Консольный ввод/вывод (console.py, promts.py)
│       ├── cli/              # Typer-команды (pas_commands, vault_commands, user_commands, config_commands)
│       ├── core/             # API-клиент, криптография, системный keyring
│       ├── schemas/          # Схемы и валидация Pydantic
│       ├── services/         # Логика хранилищ, проверка сессий, утилиты файлов
│       ├── config.py         # Загрузка и управление локальным конфигом
│       ├── decorators.py     # Декораторы проверки сессии, токенов и активного пользователя
│       ├── dependencies.py   # DI-фабрики (logger, config, keyring, password_tool)
│       ├── exceptions.py     # Кастомные исключения
│       └── main.py           # Точка входа и сборка команд Typer
├── tests/                    # Набор автотестов pytest
├── pyproject.toml            # Метаданные и зависимости проекта
├── pytest.ini                # Конфигурация запуска тестов
├── README.md                 # Документация проекта
├── realise.sh                # Скрипт развертывания и установки окружения
└── uv.lock                   # Зафиксированные зависимости менеджера uv

```

---

## Command Reference

### Base Credential Commands

Commands operate directly on the currently active vault (`pas vault set`).

| Command | Description | Example |
| --- | --- | --- |
| `pas add` | Add credential (runs interactive wizard if called without arguments) | `pas add github -u user --gen` |
| `pas list` | List all credential entries in the active vault | `pas list` |
| `pas get` | Display decrypted details of a credential entry | `pas get github` |
| `pas copy` | Copy a credential password directly to clipboard by row index | `pas copy 1` |
| `pas edit` | Modify an existing credential entry | `pas edit 1 -p newsecret` |
| `pas del` | Remove a credential entry from the vault | `pas del github` |
| `pas find` | Search entries matching a specific keyword or pattern | `pas find @gmail.com` |
| `pas export` | Export decrypted/raw vault entries to a file | `pas export backup.json` |
| `pas import` | Import entries from a file into the current vault | `pas import backup.json` |
| `pas gen` | Generate a cryptographically secure random password | `pas gen -l 32` |

---

### Vault Management (`pas vault`)

Controls the lifecycle, sync status, and active selection of local and remote vaults.

| Command | Description | Example |
| --- | --- | --- |
| `pas vault create` | Create a new vault (synced remotely by default; use `-o`/`--offline` for device-only) | `pas vault create`<br>

<br>`pas vault create --offline` |
| `pas vault list` | Display all local vaults belonging to the current user | `pas vault list` |
| `pas vault set` | Interactively select and switch the active working vault | `pas vault set` |
| `pas vault fetch` | Inspect sync status across local and remote vaults without modifying files | `pas vault fetch` |
| `pas vault sync` | Perform bidirectional synchronization (download missing/newer, push modified) | `pas vault sync` |
| `pas vault push` | Push local encrypted changes to the server (use `-f`/`--force` to overwrite) | `pas vault push`<br>

<br>`pas vault push --force` |
| `pas vault pull` | Download latest vault from server (saves to new versioned file or `--overwrite`) | `pas vault pull`<br>

<br>`pas vault pull -o` |
| `pas vault actions` | Open interactive menu for vault maintenance (rename, delete, inspect) | `pas vault actions` |
| `pas vault delete` | Interactive deletion wizard (choose: delete locally, delete remotely, or both) | `pas vault delete` |
| `pas vault change-master` | Re-encrypt local vault DEK with a new master password | `pas vault change-master` |

---

### User & Authentication (`pas user`)

Manages API authentication, user profiles, and active local user directories.

| Command | Description | Example |
| --- | --- | --- |
| `pas user register` | Register a new API account and create initial workspace | `pas user register` |
| `pas user login` | Authenticate with the remote API and save JWT tokens to system keyring | `pas user login` |
| `pas user list` | List local user profiles (`-w`/`--with-vaults`, `-s`/`--show-vaults`) | `pas user list -w -s` |
| `pas user set` | Interactively switch the active local user profile | `pas user set` |
| `pas user change-password` | Update account password on the remote authentication server | `pas user change-password` |
| `pas user delete` | Delete user account (deletes remotely by default; use `--offline` for local-only) | `pas user delete`<br>

<br>`pas user delete --offline` |

---

### Configuration (`pas config`)

Controls CLI operational parameters, base endpoints, and local state.

| Command | Description | Example |
| --- | --- | --- |
| `pas config url` | View, update, or reset the remote REST API Base URL | `pas config url` |
| `pas config token` | View or configure the API bot integration token | `pas config token` |
| `pas config reset` | Clear cached session data from keyring while keeping API URL and bot token | `pas config reset` |

---

## Workflow Example

```bash
# 1. Register or log in to your account
pas user login

# 2. Create and set an active vault
pas vault create
pas vault set

# 3. Add entries interactively
pas add

# 4. Check synchronization state and push changes
pas vault fetch
pas vault push

# 5. Access passwords
pas list
pas copy

```