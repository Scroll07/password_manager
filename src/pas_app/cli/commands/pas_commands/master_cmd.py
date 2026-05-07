import typer

from pas_app.adapters.promts import cli_password_promt
from pas_app.config import VAULTS
from pas_app.core.crypto import derive_key, encrypt_vault_passwords
from pas_app.exceptions import EchoException
from pas_app.services.file_utils import load_data
from pas_app.schemas.passwords import Passwords, EncryptedUserVault
from pas_app.config import config


def change_master(
    current_master: str = typer.Argument(
        ..., help="Введите действующий мастер-пароль для смены."
    ),
):
    """
    Команда для смены мастер-пароля.

    Требует ввода текущего и нового пароля.
    """
    data = load_data(config=config)
    
    typer.echo("Введите новый мастер-пароль в отркывшееся окно.")
    new_master_password = cli_password_promt()
    if not new_master_password:
        typer.echo("Ввод пароля отменен. ВЫХОД")
        raise typer.Exit(code=1)

    if new_master_password == current_master:
        typer.echo("Дейвствующий пароль не может совпадать с новым.")
        return

    if not typer.confirm("Изменить мастер-пароль? Это действие необратимо!"):
        typer.echo("Смена мастер-пароля отменена.")
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
    
    typer.echo("Мастер-пароль успешно изменен.")

