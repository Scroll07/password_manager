import time
import json
import os
from pathlib import Path
import typer
import base64

from pas_app.core.crypto import decrypt_vault_passwords, encrypt_vault_passwords
from pas_app.config import BASE_DIR, LAST_MATCHES, SESSION_FILE, VAULTS, UserConfig
from pas_app.schemas.passwords import Passwords, UserVault, EncryptedUserVault

# from pas_app.services.password import check_session
from pas_app.exceptions import EchoException



def dump_last_matches(
    matches: list[str],
):  # NEED TO REBUILD THIS FUNCTION TO NEW VERSION OF WORKING WITH DATA
    try:
        with open(LAST_MATCHES, "w", encoding="utf-8") as f:
            json.dump(matches, f, indent=2, ensure_ascii=False)
    except OSError:
        typer.echo("OSError")


def load_encrypted_vault(username: str) -> EncryptedUserVault:
    vault_file = VAULTS / f"{username}.json"
    try:
        with open(vault_file, "r") as f:
            data = f.read()
        encrypted = EncryptedUserVault.model_validate_json(data)
        return encrypted
    except Exception as e:
        raise EchoException(e)


def load_data(config: UserConfig) -> UserVault:
    from pas_app.services.password import get_key
    config_data = config._refresh()
    
    if config_data.default_user is None:
        raise EchoException("No logged")
    encrypted = load_encrypted_vault(config_data.default_user)
    key = get_key()
    if key is None:
        raise EchoException("Key from check_session is None")
    decoded_passwords = decrypt_vault_passwords(encrypted.encrypted_passwords, key)
    vault_data = UserVault(
        username=encrypted.username,
        salt=encrypted.salt,
        user_passwords=decoded_passwords.passwords,
    )
    return vault_data


def save_data(config: UserConfig, vault_data: UserVault) -> None:
    from pas_app.services.password import get_key

    vault_file = VAULTS / f"{vault_data.username}.json"
    if not vault_file.exists():
        raise EchoException(f"File {vault_data.username}.json does not exist")
    key = get_key()
    if key is None:
        raise EchoException("Key from check_session is None")
    encrypted_passwords = encrypt_vault_passwords(
        Passwords(passwords=vault_data.user_passwords), key
    )
    encrypted_vault = EncryptedUserVault(
        username=vault_data.username,
        salt=vault_data.salt,
        encrypted_passwords=encrypted_passwords,
    )
    with open(vault_file, "w") as f:
        f.write(encrypted_vault.model_dump_json())
    typer.echo("Данные успешно сохранены.")


def delete_file(filename: Path):
    file_to_delete = BASE_DIR / filename
    if not file_to_delete.exists():
        raise EchoException(f"Файла {filename} не обнаружено.")

    try:
        os.remove(file_to_delete)
        raise EchoException(f"Файл {filename} успешно удален.")
    except Exception as e:
        raise EchoException(f"Ошибка при удалении файла {filename}: {e}")

def get_user_vault_files() -> list[Path]:
    vaults = [v for v in VAULTS.glob("*.json")]
    return vaults    

def is_vault_files_exists() -> bool:
    vaults = get_user_vault_files()
    return True if vaults else False


def get_vault_usernames() -> list[str]:
    vaults = get_user_vault_files()
    if not vaults:
        raise EchoException("No vaults file to get username")
    usernames = []
    for v in vaults:
        with open(v, "r", encoding='utf-8') as f:
            data = f.read()
        encrypted = EncryptedUserVault.model_validate_json(data)
        usernames.append(encrypted.username)
    
    return usernames