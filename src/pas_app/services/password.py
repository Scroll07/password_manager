from datetime import datetime
import tabulate
import typer
from typing import Callable

from pas_app.adapters.promts import cli_password_promt, choose_default_user
from pas_app.core.crypto import create_random_salt, decrypt_vault_passwords, derive_key
from pas_app.config import VAULTS
from pas_app.schemas.passwords import Password, EncryptedUserVault
from pas_app.services.file_utils import load_encrypted_vault, is_vault_files_exists, get_vault_usernames
from pas_app.exceptions import EchoException
from pas_app.config import config

SESSION_TIMEOUT = 300


def check_session() -> None:
    config_data = config._refresh()

    if not is_vault_files_exists():
        typer.echo("Try to register firstly")
        raise typer.Exit(code=1)
    
    if config_data.default_user == "unauthorized":
        print(config_data.default_user, "- default user")
        print("default_user == unauthorized")
        usernames = get_vault_usernames()
        username = choose_default_user(usernames=usernames)
        config_data.default_user = username
        
    config_data.last_action = datetime.now()
    config.save_config(data=config_data)
        
        
def get_key() -> bytes:
    config_data = config._refresh()
    expired = (
        not config_data.master_password
        or not config_data.last_action
        or (datetime.now() - config_data.last_action).total_seconds() > SESSION_TIMEOUT
    )

    if expired:
        master_password = cli_password_promt()
    else:
        master_password = config_data.master_password

    encrypted_vault = load_encrypted_vault(config_data.default_user)

    key = derive_key(master_password, encrypted_vault.salt)  # type: ignore
    decrypt_vault_passwords(encrypted_vault.encrypted_passwords, key)

    config_data.master_password = master_password
    config.save_config(data=config_data)
    
    return key


def create_user_vault(username: str):
    new_vault = VAULTS / f"{username}.json"
    if new_vault.exists():
        raise EchoException(f"File {username}.json already exists")

    salt = create_random_salt()
    vault_data = EncryptedUserVault(
        username=username, salt=salt, encrypted_passwords=""
    )

    data = vault_data.model_dump_json()
    with open(new_vault, "w") as f:
        f.write(data)


def print_passwords(passwords: list[Password], show: bool = False) -> None:
    if not passwords:
        typer.echo("Записей нет")
        return

    headers = ["№", "Метка", "Логин", "Пароль", "Заметка"]
    rows = []

    for i, pas in enumerate(passwords, start=1):
        try:
            match = pas.service
            username = pas.username
            password = pas.password if show else "******"
            note = pas.note
            rows.append([i, match, username, password, note])
        except Exception as e:
            typer.echo(f"Ошибка: {e}")
            raise typer.Exit(code=1)

    if rows:
        typer.echo(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))
        
        
        
        
# DECORATOR
      
from functools import wraps   
        
def check_session_dec(func: Callable):
    @wraps(func)
    def wrapper(*args, **kwargs):
        check_session()
        result = func(*args, **kwargs)
        return result
    return wrapper

