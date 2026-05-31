import typer

from pas_app.adapters.promts import cli_password_promt
from pas_app.config import VAULTS
from pas_app.core.crypto import derive_key, encrypt_vault_passwords
from pas_app.exceptions import EchoException
from pas_app.services.file_utils import load_data
from pas_app.schemas.passwords import Passwords, EncryptedUserVault
from pas_app.config import get_config


def change_master(
    current_master: str = typer.Argument(
        ..., help="Current master password for change."
    ),
):
    """
    Change the master password for local vault.

    The command requires entering the current password and a new password.
    The operation is irreversible and will re-encrypt all stored passwords
    with the new master password.

    Examples:
        pas user change-master <current-password>

    You will be prompted to enter a new password in a secure input window.
    Confirm the change when prompted.
    """
    config = get_config()
    data = load_data(config=config)
    
    typer.echo("Enter new master password in the opened window.")
    new_master_password = cli_password_promt()
    if not new_master_password:
        typer.echo("Password input was canceled. EXIT")
        raise typer.Exit(code=1)

    if new_master_password == current_master:
        typer.echo("Current password cannot match the new password.")
        return

    if not typer.confirm("Change master password? This action is irreversible!"):
        typer.echo("Master password change was canceled.")
        return

    new_key = derive_key(new_master_password, data.salt)
    encrypted_passwords = encrypt_vault_passwords(Passwords(passwords=data.user_passwords), new_key)
    
    encrypted_vault = EncryptedUserVault(
        username=data.username,
        salt=data.salt,
        encrypted_passwords=encrypted_passwords
    )
    
    vault_file = VAULTS / f"{data.username}.json"
    if not vault_file.exists():
        raise EchoException(f"File {data.username}.json does not exist")
    with open(vault_file, "w") as f:
        f.write(encrypted_vault.model_dump_json())
    
    typer.echo("Master password was successfully changed.")

