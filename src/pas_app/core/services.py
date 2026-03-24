import base64
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import time
import typer


from pas_app.adapters.promt_gui import gui_password_prompt
from pas_app.core.crypto import decrypt_data, encrypt_data
from pas_app.config import BASE_DIR, LAST_MATCHES, SALT_FILE, SESSION_FILE, STORE

SESSION_TIMEOUT = 300



def get_master_key(master_password: str) -> bytes:
    """Генерирует ключ из мастер-пароля с использованием соли."""
    if not SALT_FILE.exists():
        salt = os.urandom(16)  # Генерация случайной соли (16 байтов)
        SALT_FILE.write_bytes(salt)  # Сохранение соли в файл
    else:
        salt = SALT_FILE.read_bytes()  # Чтение существующей соли
    # Deriving ключа с PBKDF2
    kdf = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 100000, dklen=32)
    key = base64.urlsafe_b64encode(kdf)  # Кодировка в формат для Fernet
    return key




def save_session(session_key: bytes):
    session_start_time = time.time()
    data = {
        'start_time': session_start_time,
        'key': base64.urlsafe_b64encode(session_key).decode('utf-8') # type: ignore
    }
    with open(SESSION_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f)

def check_session(force_prompt: bool = False):
    if not force_prompt and SESSION_FILE.exists():
        try:
            with open(SESSION_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                session_start_time = data['start_time']
                session_key = base64.urlsafe_b64decode(data['key'])
            if time.time() - session_start_time < SESSION_TIMEOUT:
                save_session(session_key)
                return session_key
        except (json.JSONDecodeError, KeyError, ValueError, base64.binascii.Error): # type: ignore
            pass

    typer.echo('Введите действующий мастер-пароль для продолжения.')
    master_password = gui_password_prompt()
    if not master_password:
        typer.echo('Ввод пароля отменен.')
        raise typer.Exit()
    
    try:
        key = get_master_key(master_password)
        if STORE.exists():
            encrypted = STORE.read_bytes()
            _ = decrypt_data(encrypted, key)
        save_session(key)
        return key
    except ValueError as e:
        typer.echo(f"Ошибка: {str(e)}")
        raise typer.Exit()
    


def dump_last_matches(matches: list[str]):
    try:
        with open(LAST_MATCHES, 'w', encoding='utf-8') as f:
            json.dump(matches, f, indent=2, ensure_ascii=False)
    except OSError: 
        typer.echo('OSError')



def load_data():
    key = check_session()
    if not STORE.exists():
        return {}
    try:
        encrypted = STORE.read_bytes()
        return decrypt_data(encrypted, key)
    except ValueError as e:
        typer.echo(f'Ошибка: {str(e)}')
        return {}




def save_data(data: dict):
    key = check_session()
    encrypted = encrypt_data(data, key)
    STORE.write_bytes(encrypted)
    typer.echo("Данные успешно сохранены.")



def delete_file(filename: Path):
    file_to_delete = BASE_DIR / filename
    if not file_to_delete.exists():
        typer.echo(f'Файла {filename} не обнаружено.')
        return
    
    try:
        os.remove(file_to_delete)
        typer.echo(f'Файл {filename} успешно удален.')
    except Exception as e:
        typer.echo(f'Ошибка при удалении файла {filename}: {e}')