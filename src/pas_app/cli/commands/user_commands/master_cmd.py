import time
import json
from cryptography.fernet import InvalidToken
import typer

from pas_app.adapters.console import clear_console
from pas_app.adapters.promts import cli_password_promt
from pas_app.core.crypto import (
    decrypt_dek, 
    decrypt_vault_passwords, 
    derive_key,
    encrypt_dek
)
from pas_app.schemas.passwords import EncryptedUserVault
from pas_app.services.file_utils import (
    load_encrypted_vault,
    create_vault_path
)
from pas_app.dependencies import get_keyring_tool


def _local_attempt_decrypt_vault(username: str, vault_name: str, text: str) -> tuple[EncryptedUserVault, str] | tuple[None, None]:
    encrypted_vault = load_encrypted_vault(username=username, vault_name=vault_name)
    clear_console()
    typer.echo(text)
    master_password = cli_password_promt()
    kek = derive_key(master_password=master_password, salt_b64=encrypted_vault.salt)
    dek = decrypt_dek(kek=kek, encrypted_dek_str=encrypted_vault.encrypted_dek)
    try:
        passwords = decrypt_vault_passwords(encrypted_passwords=encrypted_vault.encrypted_passwords, key=dek)
    except InvalidToken:
        typer.echo("Wrong master password")
        time.sleep(2)
        return None, None
    return encrypted_vault, master_password

def change_master():
    """
    Change the master password for local vault.

    The command requires entering the current password and a new password.
    The operation is irreversible and will re-encrypt all stored passwords
    with the new master password.

    Examples:
        pas user change-master <current-password>

    """
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    
    encrypted_vault, current_master_password = None, None
    username = keyring_data.current_user
    vault_name = keyring_data.current_vault
    i = 0
    while i < 5 and current_master_password is None:
        encrypted_vault, current_master_password = _local_attempt_decrypt_vault(
            username=username,
            vault_name=vault_name, 
            text="Enter master password of current vault"
        )
    if current_master_password is None or encrypted_vault is None:
        typer.echo("Too many attempts")
        return

    typer.echo("Enter new master password.")
    new_master_password = cli_password_promt()
    if not new_master_password:
        typer.echo("Password input was canceled. EXIT")
        raise typer.Exit(code=1)
    
    if new_master_password == current_master_password:
        typer.echo("Current password cannot match the new password.")
        return

    if not typer.confirm("Change master password? This action is irreversible!"):
        typer.echo("Master password change was canceled.")
        return

    current_kek = derive_key(master_password=current_master_password, salt_b64=encrypted_vault.salt)
    new_kek = derive_key(master_password=new_master_password, salt_b64=encrypted_vault.salt)
    dek = decrypt_dek(kek=current_kek, encrypted_dek_str=encrypted_vault.encrypted_dek)
    new_encrypted_dek = encrypt_dek(dek=dek, new_kek=new_kek)

    encrypted_vault.encrypted_dek = new_encrypted_dek
    
    vault_path = create_vault_path(username=username, vault_name=vault_name)
    with open(vault_path, 'w', encoding='utf-8') as f:
        json.dump(encrypted_vault.model_dump(), f, indent=4)
    
    typer.echo("Master password was successfully changed.")

