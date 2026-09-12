from datetime import datetime
import tabulate
import typer
from typing import Callable, Literal

from pas_app.adapters.promts import (
    cli_password_promt, 
    choose_current_user,
    choose_current_vault
)
from pas_app.core.crypto import create_random_salt, decrypt_vault_passwords, derive_key
from pas_app.schemas.passwords import Password, EncryptedUserVault
from pas_app.services.file_utils import (
    create_vault_path,
    load_encrypted_vault,
    get_vault_usernames,
    get_user_vault_files
)
from pas_app.exceptions import EchoException
from pas_app.config import get_config
from pas_app.core.keyring import get_keyring_tool


SESSION_TIMEOUT = 300


def check_session() -> None:
    keyring = get_keyring_tool()
    keyring_data = keyring.load()

    if not keyring_data.current_user:
        # choose current user
        # username = ...
        # keyring_data.current_user = username
        
        usernames = get_vault_usernames()
        if not usernames:
            raise EchoException("There are no accounts on this device.\nTry to sync accounts or create new.")
        selected_username = choose_current_user(usernames=usernames, current_username="Not selected")
        keyring_data.current_user = selected_username
        
    if not keyring_data.current_vault:
        # choose current vault
        # vault_name = ...
        # keyring_data.current_vault = vault_name

        vaults = get_user_vault_files(username=keyring_data.current_user)
        if not vaults:
            raise EchoException(f"There are no vaults on this device for {keyring_data.current_user}.\nTry to sync accounts or create new.")
        vault_names = [v.parts[0] for v in vaults]
        selected_vault = choose_current_vault(vault_names=vault_names, current_vault="Not selected")
        keyring_data.current_vault = selected_vault


    
    vault_file = create_vault_path(username=keyring_data.current_user, vault_name=keyring_data.current_vault)
    if not vault_file.exists():
        raise FileExistsError(f'{vault_file} does not exist')
        
    encrypted_vault_data = load_encrypted_vault(username=keyring_data.current_user, vault_name=keyring_data.current_vault)
    if keyring_data.current_user != encrypted_vault_data.username:
        raise ValueError()
    
    keyring.save(data=keyring_data)        
        
        
def get_key() -> bytes:
    config = get_config()
    config_data = config.load_config()
    expired = (
        not config_data.keyring.master_password
        or not config_data.keyring.last_action
        or (datetime.now() - config_data.keyring.last_action).total_seconds() > SESSION_TIMEOUT
    )

    if expired:
        master_password = cli_password_promt().strip()
    else:
        master_password = config_data.keyring.master_password

    encrypted_vault = load_encrypted_vault(config_data.local.DEFAULT_USER)

    kek = derive_key(master_password, encrypted_vault.salt)
    dek = 
    decrypt_vault_passwords(encrypted_vault.encrypted_passwords, key)

    config_data.keyring.master_password = master_password
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


def print_passwords(passwords: list[Password], show: bool = False, check: bool = False) -> None:
    if not passwords:
        typer.echo("Записей нет")
        return
    rows = []
    if not check:
        headers = ["№", "Метка", "Логин", "Пароль", "Заметка"]
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
    else:
        headers = ["№", "Метка", "Логин", "Пароль", "Strength"]
        for i, pas in enumerate(passwords, start=1):
            try:
                match = pas.service
                username = pas.username
                password = pas.password if show else "******"
                strength = check_password_strength(password=pas.password)
                rows.append([i, match, username, password, strength])
            except Exception as e:
                typer.echo(f"Ошибка: {e}")
                raise typer.Exit(code=1)

    if rows:
        typer.echo(tabulate.tabulate(rows, headers=headers, tablefmt="grid"))
        
        
def find_digits_in_a_row(row: str) -> int:
    result = 0
    left = 0
    while left < len(row):
        while left < len(row) and not row[left].isdigit():
            left += 1
        right = left + 1
        while right < len(row) and row[right].isdigit():
            right += 1
        result = max(result, right - left + 1)
        left = right
    return result


def is_common_pattern(password: str) -> bool:
    """Check for common weak patterns (sequential, repeated chars, etc)."""
    common_patterns = [
        "123", "321", "012", "456", "789",
        "abc", "bcd", "xyz", "qwerty", "qwertyuiop",
        "aaa", "bbb", "ccc", "111", "222", "000",
        "password", "pass", "admin", "user", "test"
    ]
    
    pwd_lower = password.lower()
    for pattern in common_patterns:
        if pattern in pwd_lower:
            return True
    return False


PASSWORD_STRENGTH_LEVEL = Literal["HIGH", "MEDIUM", "LOW"]
def check_password_strength(password: str) -> PASSWORD_STRENGTH_LEVEL:
    score = 0
    
    data_folder = BASE_DIR / "data"
    data_files = [f for f in data_folder.rglob("*.txt")]
    for file in data_files:
        if not file.exists():
            continue
        data = file.read_text()
        if password in data:
            return "LOW"
    
    if is_common_pattern(password):
        return "LOW"
    
    if len(password) < 8:
        return "LOW"
    elif len(password) >= 16:
        score += 3
    elif len(password) >= 12:
        score += 2
    else:
        score += 1
    
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    variety = sum([has_upper, has_lower, has_digit, has_special])
    if variety >= 4:
        score += 3
    elif variety >= 3:
        score += 2
    elif variety >= 2:
        score += 1
    else:
        return "LOW"
    
    digits = find_digits_in_a_row(row=password)
    
    if digits >= 3:
        score -= 1
    
    if score >= 6:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    else:
        return "LOW"
        

# def get_



# DECORATOR
from functools import wraps   
        
def check_session_dec(func: Callable):
    @wraps(func)
    def wrapper(*args, **kwargs):
        check_session()
        result = func(*args, **kwargs)
        return result
    return wrapper

