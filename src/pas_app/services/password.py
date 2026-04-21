from datetime import datetime
import typer

from cryptography.fernet import InvalidToken

from pas_app.adapters.promts import gui_password_prompt, cli_password_promt
from pas_app.core.crypto import create_random_salt, decrypt_vault_passwords, encrypt_vault_passwords, derive_key
from pas_app.config import VAULTS
from pas_app.schemas.passwords import Password, UserVault, EncryptedUserVault
from pas_app.schemas.state import State
from pas_app.services.file_utils import load_data, load_encrypted_vault

SESSION_TIMEOUT = 300







def check_session(state: State):
    username = state.current_user
    
    if username is None:
        raise ValueError("No logged")

    encrypted_vault = load_encrypted_vault(username)
    
    vault_file = VAULTS / f"{username}.json"
    if not vault_file.exists():
        raise ValueError(f"File {username}.json does not exist")
    delta = datetime.now() - state.last_action
    if delta.total_seconds() > 300 or master_password is None:
        # master_password = gui_password_prompt()
        master_password = cli_password_promt()
        if not master_password:
            typer.echo('Ввод пароля отменен.')
            raise typer.Exit()
    try:
        salt = encrypted_vault.salt
        key = derive_key(master_password, salt)
        _ = decrypt_vault_passwords(encrypted_vault.encrypted_passwords, key)
        
        return key
    except InvalidToken as e:
        typer.echo("Неправильный мастер-пароль")
        raise typer.Exit()
    




#----NEW----#    
    

def create_user_vault(username: str):
    new_vault = VAULTS / f"{username}.json"
    if new_vault.exists():
        raise ValueError(f"File {username}.json already exists")
    
    salt = create_random_salt()
    vault_data = EncryptedUserVault(
        username=username,
        salt=salt,
        encrypted_passwords=""
    )
    
    
    data = vault_data.model_dump_json()
    with open(new_vault, "w") as f:
        f.write(data)
        
        


