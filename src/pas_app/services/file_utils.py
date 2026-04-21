import json
import os
from pathlib import Path
import typer


from pas_app.core.crypto import decrypt_vault_passwords, encrypt_vault_passwords
from pas_app.config import BASE_DIR, LAST_MATCHES, VAULTS
from pas_app.schemas.passwords import Passwords, UserVault, EncryptedUserVault
from pas_app.services.password import check_session
from pas_app.schemas.state import State
from pas_app.exceptions import EchoException




# def save_session(session_key: bytes):
#     session_start_time = time.time()
#     data = {
#         'start_time': session_start_time,
#         'key': base64.urlsafe_b64encode(session_key).decode('utf-8') # type: ignore
#     }
#     with open(SESSION_FILE, 'w', encoding='utf-8') as f:
#         json.dump(data, f)


def dump_last_matches(matches: list[str]):
    try:
        with open(LAST_MATCHES, 'w', encoding='utf-8') as f:
            json.dump(matches, f, indent=2, ensure_ascii=False)
    except OSError: 
        typer.echo('OSError')

def load_encrypted_vault(username: str) -> EncryptedUserVault:
    vault_file = VAULTS / f"{username}.json"
    try:
        with open(vault_file, "r") as f:
            data = f.read()
        encrypted = EncryptedUserVault.model_validate_json(data)
        return encrypted
    except Exception as e:
        raise EchoException(e)
    
    
def load_data(state: State) -> UserVault:
    if state.current_user is None:
        raise EchoException("No logged")
    encrypted = load_encrypted_vault(state.current_user)
    key = check_session(state)
    decoded_passwords = decrypt_vault_passwords(encrypted.encrypted_passwords, key)
    vault_data = UserVault(
        username=encrypted.username,
        salt=encrypted.salt,
        user_passwords=decoded_passwords.passwords
    )
    return vault_data
    
    




def save_data(state: State ,vault_data: UserVault):
    vault_file = VAULTS / f"{vault_data.username}.json"
    if not vault_file.exists():
        raise EchoException(f"File {vault_data.username}.json does not exist") 
    key = check_session(state)
    encrypted_passwords = encrypt_vault_passwords(Passwords(passwords=vault_data.user_passwords), key)
    encrypted_vault = EncryptedUserVault(
        username=vault_data.username,
        salt=vault_data.salt,
        encrypted_passwords=encrypted_passwords
    )
    with open(vault_file, "w") as f:
        f.write(encrypted_vault.model_dump_json())
    typer.echo("Данные успешно сохранены.")



def delete_file(filename: Path):
    file_to_delete = BASE_DIR / filename
    if not file_to_delete.exists():
        raise EchoException(f'Файла {filename} не обнаружено.')
    
    try:
        os.remove(file_to_delete)
        raise EchoException(f'Файл {filename} успешно удален.')
    except Exception as e:
        raise EchoException(f'Ошибка при удалении файла {filename}: {e}')
        