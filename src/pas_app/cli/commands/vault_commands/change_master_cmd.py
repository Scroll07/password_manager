import asyncio
from pathlib import Path
import json
from cryptography.fernet import InvalidToken
from pydantic import ValidationError
import typer

from pas_app.adapters.console import clear_console
from pas_app.adapters.promts import cli_password_promt, choose_vault
from pas_app.core.crypto import (
    decrypt_dek, 
    decrypt_vault_passwords, 
    derive_key,
    encrypt_dek
)
from pas_app.schemas.vaults import EncryptedUserVault
from pas_app.services.file_utils import (
    create_vault_path,
    get_user_vault_files
)
from pas_app.dependencies import get_keyring_tool


async def _local_attempt_decrypt_vault(path: Path, text: str) -> tuple[EncryptedUserVault, str] | tuple[None, None]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            encrypted_vault = EncryptedUserVault.model_validate_json(f.read())
    except ValidationError as e:
        typer.echo(f"[ERROR] Wrong structure of vault {path}")
        raise typer.Exit(code=1)
        
    clear_console()
    typer.echo(text)
    master_password = cli_password_promt()
    kek = derive_key(master_password=master_password, salt_b64=encrypted_vault.salt)
    try:
        dek = decrypt_dek(kek=kek, encrypted_dek_str=encrypted_vault.encrypted_dek)
        passwords = decrypt_vault_passwords(encrypted_passwords=encrypted_vault.encrypted_passwords, key=dek)
    except InvalidToken:
        return None, None
    return encrypted_vault, master_password

async def change_master():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    
    vaults_paths = get_user_vault_files(username=username)
    choosed_vault = choose_vault(vaults=vaults_paths, msg="Choose vault to change master password")
    
    
    encrypted_vault, current_master_password = None, None
    vault_name = keyring_data.current_vault
    
    for attempt in range(1, 4):
        encrypted_vault, current_master_password = await _local_attempt_decrypt_vault(
            path=choosed_vault,
            text="Enter current master password for choosed vault: "
        )
        if current_master_password is None or encrypted_vault is None:
            clear_console()
            typer.echo(f"[ERROR] Wrong master password\n{3-attempt} attempts remain")
            await asyncio.sleep(2)
            continue
        break
    else:
        typer.echo("Too many attempts")
        raise typer.Exit(code=1)
        

    new_master_password = cli_password_promt("Enter new master password: ")
    if not new_master_password:
        typer.echo("[ERROR] Password input was canceled. EXIT")
        raise typer.Exit(code=1)
    
    if new_master_password == current_master_password:
        typer.echo("[ERROR] Current password cannot match the new password.")
        raise typer.Exit(code=1)

    if not typer.confirm("Change master password? This action is irreversible!"):
        typer.echo("[ERROR] Master password changing was canceled.")
        raise typer.Exit(code=1)

    current_kek = derive_key(master_password=current_master_password, salt_b64=encrypted_vault.salt)
    new_kek = derive_key(master_password=new_master_password, salt_b64=encrypted_vault.salt)
    dek = decrypt_dek(kek=current_kek, encrypted_dek_str=encrypted_vault.encrypted_dek)
    new_encrypted_dek = encrypt_dek(dek=dek, new_kek=new_kek)

    encrypted_vault.encrypted_dek = new_encrypted_dek
    
    vault_path = create_vault_path(username=username, vault_name=vault_name)
    with open(vault_path, 'w', encoding='utf-8') as f:
        json.dump(encrypted_vault.model_dump(), f, indent=4)
    
    typer.echo("Master password was successfully changed.")

