import asyncio
import json
from pathlib import Path
import time
import typer
from cryptography.fernet import InvalidToken
from pydantic import ValidationError

from pas_app.core.logger import get_logger
from pas_app.core.crypto import (
    decrypt_vault_passwords, 
    encrypt_vault_passwords,
    derive_key,
    create_dek,
    create_random_salt
)
from pas_app.config import UserConfig
from pas_app.schemas.passwords import Passwords
from pas_app.core.settings import (
    VAULTS,
    LAST_MATCHES
)

# from pas_app.services.password import check_session
from pas_app.exceptions import EchoException
from pas_app.adapters.promts import (
    select_vault_name,
    select_master_password
)
from pas_app.schemas.vaults import EncryptedUserVault, LocalVaultInfo, LocalVaultsData, UserVault, VaultPrintData


logger = get_logger()


def create_vault_path(username: str, vault_name: str) -> Path:
    def _validate_vault_name(vault_name: str) -> str:
        if vault_name.endswith('.json'):
            vault_name = vault_name[:-5]
        return vault_name
    vault_name = _validate_vault_name(vault_name=vault_name)
    
    dir = VAULTS / username
    dir.mkdir(exist_ok=True, parents=True)
    return dir / f'{vault_name}.json'


def load_encrypted_vault(username: str, vault_name: str) -> EncryptedUserVault:
    vault_file = create_vault_path(username=username, vault_name=vault_name)
    try:
        with open(vault_file, "r") as f:
            data = f.read()
        encrypted = EncryptedUserVault.model_validate_json(data)
        return encrypted
    except Exception as e:
        raise EchoException(e)


def load_data(username: str, vault_name: str) -> UserVault:
    from pas_app.services.password import get_key
    encrypted = load_encrypted_vault(username=username, vault_name=vault_name)
    try:
        key = get_key()
    except InvalidToken:
        typer.echo("Wrong master password")
        raise typer.Exit(code=1)
    decoded_passwords = decrypt_vault_passwords(encrypted.encrypted_passwords, key)
    vault_data = UserVault(
        id=encrypted.id,
        name=vault_name,
        salt=encrypted.salt,
        user_passwords=decoded_passwords.passwords,
        encrypted_dek=encrypted.encrypted_dek,
        version=encrypted.version
    )
    return vault_data


def save_data(username: str, vault_name: str, vault_data: UserVault) -> None:
    from pas_app.services.password import get_key

    vault_file = create_vault_path(username=username, vault_name=vault_name)
    if not vault_file.exists():
        raise EchoException(f"File does not exist")
    key = get_key()
    encrypted_passwords = encrypt_vault_passwords(
        Passwords(passwords=vault_data.user_passwords), key
    )
    encrypted_vault = EncryptedUserVault(
        id=vault_data.id,
        name=vault_data.name,
        salt=vault_data.salt,
        encrypted_passwords=encrypted_passwords,
        encrypted_dek=vault_data.encrypted_dek,
        version=vault_data.version
    )
    with open(vault_file, "w") as f:
        f.write(encrypted_vault.model_dump_json())

def create_vault(username: str, vault_name: str, master_password: str) -> None:
    new_vault_path = create_vault_path(username=username, vault_name=vault_name)
    if new_vault_path.exists():
        raise FileExistsError('Vault with such name already exists')
    
    salt = create_random_salt()
    kek = derive_key(master_password=master_password, salt_b64=salt)
    encrypted_dek_str = create_dek(kek=kek)
    data = EncryptedUserVault(
        id=None,
        name=vault_name,
        salt=salt,
        encrypted_dek=encrypted_dek_str,
        encrypted_passwords='',
        version=1
    )
    with open(new_vault_path, 'w', encoding='utf-8') as f:
        json.dump(data.model_dump(), f, indent=4)
    
    


def get_user_vault_files(username: str) -> list[Path]:
    user_dir = VAULTS / username
    if not user_dir.is_dir():
        raise ValueError(f"{user_dir} is not a directory")
    return [v for v in user_dir.glob("*.json") if v.is_file()]

def get_vault_usernames_with_vault() -> list[str]:
    user_folders = [f for f in VAULTS.glob("*") if f.is_dir()]
    if not user_folders:
        logger.warning(f"No vault folders found in {VAULTS}")
        raise EchoException("No vaults file to get username")

    # Пользователь считается валидным, если в его папке лежит хотя бы один .json
    usernames = [
        f.name for f in user_folders 
        if any(v.is_file() for v in f.glob("*.json"))
    ]
    return usernames

def get_vault_username_folders() -> list[str]:
    user_folders = [f for f in VAULTS.glob('*') if f.is_dir()]
    if not user_folders:
        return []
    usernames = []
    for folder in user_folders:
        folder_name = folder.name
        usernames.append(folder_name)
    return usernames

def get_VaultPringData(vaults: list[Path]) -> list[VaultPrintData]:
    result = []
    for v in vaults:
        try:
            with open(v, 'r', encoding='utf-8') as f:
                encrypted = EncryptedUserVault.model_validate_json(f.read())
        except ValidationError as e:
            logger.error(f"Validation error of file {v}\n{e}")
            typer.echo(f"Validation error of file {v}\nSkipping...\n")
            time.sleep(0.5)
            continue
        result.append(
            VaultPrintData(
                filename=v.name,
                vault_name=encrypted.name
            )
        )
    return result

async def load_encrypted_vault_by_path(path: Path) -> EncryptedUserVault | None:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            encrypted = EncryptedUserVault.model_validate_json(f.read())
            return encrypted
    except ValidationError as e:
        logger.error(f"Validation error of file {path}\n{e}")
        typer.echo(f"Validation error of file {path}\nSkipping...\n")
        await asyncio.sleep(0.5)
        return None
    
async def get_local_user_vaults_data(username: str) -> LocalVaultsData | None:
    vault_paths = get_user_vault_files(username=username)
    if not vault_paths:
        return None
    
    synced: dict[int, LocalVaultInfo] = {}
    unpushed: list[LocalVaultInfo] = []
    
    for path in vault_paths:
        encrypted = await load_encrypted_vault_by_path(path=path)
        if encrypted is None:
            continue
        
        if encrypted.id == None:
            unpushed.append(
                LocalVaultInfo(
                    vault=encrypted,
                    path=path
                )
            )
        else:
            synced[encrypted.id] = LocalVaultInfo(
                vault=encrypted,
                path=path
            )
        
    return LocalVaultsData(
        synced=synced,
        unpushed=unpushed
    )