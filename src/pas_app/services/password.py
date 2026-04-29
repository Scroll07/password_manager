from datetime import datetime
import tabulate
import typer

from cryptography.fernet import InvalidToken

from pas_app.adapters.promts import gui_password_prompt, cli_password_promt
from pas_app.core.crypto import create_random_salt, decrypt_vault_passwords, encrypt_vault_passwords, derive_key
from pas_app.config import VAULTS
from pas_app.schemas.passwords import Password, Passwords, UserVault, EncryptedUserVault
from pas_app.schemas.state import State
from pas_app.services.file_utils import load_encrypted_vault
from pas_app.exceptions import EchoException


SESSION_TIMEOUT = 300







def check_session(state: State):
    if state.current_user is None:
        raise EchoException("No logged user")
    
    expired = (
        state.master_password is None
        or state.last_action is None
        or (datetime.now() - state.last_action).total_seconds() > SESSION_TIMEOUT
    )    

    if expired:
        master_password = cli_password_promt()
        if not master_password:
            raise EchoException("Cancelled")
    else:
        master_password = state.master_password
        
    encrypted_vault = load_encrypted_vault(state.current_user)
    
    key = derive_key(master_password, encrypted_vault.salt) # type: ignore
    decrypt_vault_passwords(encrypted_vault.encrypted_passwords, key)
    
    state.master_password = master_password
    state.last_action = datetime.now()
    
    return key
    


    

def create_user_vault(username: str):
    new_vault = VAULTS / f"{username}.json"
    if new_vault.exists():
        raise EchoException(f"File {username}.json already exists")
    
    salt = create_random_salt()
    vault_data = EncryptedUserVault(
        username=username,
        salt=salt,
        encrypted_passwords=""
    )
    
    data = vault_data.model_dump_json()
    with open(new_vault, "w") as f:
        f.write(data)
        
        
        
def print_passwords(passwords: list[Password], show: bool = False) -> None:
    if not passwords:
        typer.echo('Записей нет')
        return    
    
    headers = ['№','Метка', "Логин", 'Пароль', 'Заметка']
    rows = []

    for i, pas in enumerate(passwords, start=1):
        try:
            match = pas.service
            username = pas.username
            password = pas.password if show else '******'
            note = pas.note
            rows.append([i, match, username, password, note])
        except Exception as e:
            typer.echo(f"Ошибка: {e}")
            raise typer.Exit(code=1)

        
    if rows:
        typer.echo(tabulate.tabulate(rows, headers=headers, tablefmt='grid'))


