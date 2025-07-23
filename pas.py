import typer, secrets, getpass
import os
import json
import pyperclip
from pathlib import Path
import tabulate
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import base64
import time
import tkinter as tk
from tkinter import simpledialog

def gui_password_prompt():
    root = tk.Tk()
    root.withdraw()  # Скрыть основное окно
    password = simpledialog.askstring("Мастер-пароль", "Введите мастер пароль:", show='*')
    root.destroy()
    return password

BASE_DIR = Path(__file__).resolve().parent
STORE = BASE_DIR / 'store.bin'
LAST_MATCHES = BASE_DIR / 'last_matches.json'
#MASTER_HASH = BASE_DIR / 'master_hash.json'
SALT_FILE = BASE_DIR / 'salt_file.bin'

session_key = None
session_start_time = None
SESSION_TIMEOUT = 300

app = typer.Typer(help="""
    Менеджер паролей - безопасное хранение логинов и паролей.
    
    Основной рабочий процесс:
    1. Добавьте записи: pas.py add <сервис> -u <логин> --gen
    2. Просмотрите список: pas.py list
    3. Найдите нужную: pas.py get <сервис>
    4. Скопируйте пароль: pas.py copy <номер>
    
    Все данные хранятся в зашифрованном файле store.json
    
    Для справки по команде: pas.py <команда> --help
    """,
    no_args_is_help=True)

def check_session(force_prompt: bool = False):
    global session_key, session_start_time
    if session_key is not None and not force_prompt:
        if time.time() - session_start_time < SESSION_TIMEOUT:
            session_start_time = time.time()
            return session_key
        else:
            typer.echo("Сессия истекла по таймауту.")
            session_key = None
            session_start_time = None

    master_password = gui_password_prompt()
    try:
        key = get_master_key(master_password)
        if STORE.exists():
            encrypted = STORE.read_bytes()
            _ = decrypt_data(encrypted, key)
        session_key = key
        session_start_time = time.time()
        return key
    except ValueError as e:
        typer.echo(f"Ошибка: {str(e)}")
        raise typer.Exit()

def dump_last_matches(matches):
    try:
        with open(LAST_MATCHES, 'w', encoding='utf-8') as f:
            json.dump(matches, f, indent=2, ensure_ascii=False)
    except OSError: 
        typer.echo('OSError')     

def encrypt_data(data: dict, key: bytes) -> bytes:
    json_str = json.dumps(data, ensure_ascii=False)
    bytes_data = json_str.encode('utf-8')
    cipher = Fernet(key)
    encrypted = cipher.encrypt(bytes_data)
    return encrypted

def decrypt_data(encrypted: bytes, key: bytes) -> dict:
    cipher = Fernet(key)
    try:
        decrypted = cipher.decrypt(encrypted)
        json_str = decrypted.decode('utf-8')
        data = json.loads(json_str)
        return data
    except InvalidToken:
        raise ValueError("Неверный ключ или повреждённые данные.")
    
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

@app.command()
def add(
    service: str = typer.Argument(..., help="Название сервиса (например: github, vk, yandex)"),
    username: str = typer.Option(..., '-u', '--username', help="Имя пользователя или email"),
    password: str = typer.Option(None, '-p', '--password', help="Пароль (если не указан, используйте --gen)"),
    note: str = typer.Option(None, '--note', help="Дополнительная заметка или описание"),
    gen: bool = typer.Option(False, '--gen', help="Сгенерировать случайный пароль"),
    length: int = typer.Option(16, '--length', help="Длина генерируемого пароля (по умолчанию: 16)")
):
    '''
    Сохранение Логина/Пароля.
    Примеры:
      pas.py add github -u myuser -p mypass123
      pas.py add vk -u user@email.com --gen --length 20
      pas.py add work-email -u john@company.com --gen --note "Рабочая почта"
    '''
    if password is not None:
        if gen:
            typer.echo('Нельзя вводить одновременно -p И --gen \n ВЫХОД')
            return
    elif password is None and gen:
        password = secrets.token_urlsafe(length)
    elif password is None and gen == False:
        typer.echo('Нужно указать либо -p либо --gen')
        return


    data = load_data()

    labels = set(data)
    base = service.lower()
    candidate = base
    i=1
    while candidate in labels:
        candidate = base + '-' + str(i)
        i+=1
    entry = {"username": username, "password": password, "note": note}
    data[candidate] = entry
    save_data(data)

@app.command()
def list():
    '''
    Показать список всех сохраненных меток сервисов.
    Выводит отсортированный список всех доступных записей.
    '''
    data = load_data()
    
    labels = sorted(data.keys())
    table = [[label] for label in labels]
    if not labels:
        typer.echo('Записей не найдено.')
        return
    else:
        typer.echo(tabulate.tabulate(table, headers=["Метки"], tablefmt="simple"))

@app.command()
def get(
    service: str = typer.Argument(..., help='Метка сервиса (например: github) или "all" для всех записей'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)')
):
    '''
    Показать информацию о записях по метке или все записи.
    
    Поддерживает поиск по началу метки - "github" найдет github, github-1, github-2.
    По умолчанию пароли скрыты символами ******, используйте --show для отображения.
    
    Примеры:
      pas.py get github           # Все записи, начинающиеся с "github", пароли скрыты
      pas.py get github --show    # То же, но с открытыми паролями
      pas.py get all              # Все записи, пароли скрыты
      pas.py get all --show       # Все записи с открытыми паролями
    '''
    if not STORE.exists():
        typer.echo('Записей нет')
        return

    data = load_data()

    if not data:
        typer.echo('Записей нет')
        return

    if service.lower() == '.':
        matches = sorted(data.keys())
    else:
        matches = sorted([key for key in data if key.lower().startswith(service.lower())])
    if not matches:
        typer.echo('Записей нет')
        return    
    headers = ['№','Метка', "Логин", 'Пароль', 'Заметка']
    rows = []

    for i, match in enumerate(matches, start=1):
        try:
            value = data[match]
            username = value["username"]
            password = value["password"] if show else '******'
            note = value.get("note", "")
            rows.append([i, match, username, password, note])
        
        except KeyError as e:
            typer.echo(f"В записи {match} нет ключа {e.args[0]}. Пропускаем.")
        except TypeError as e:
            typer.echo(f"Неверная структура в {match}: {e}. Пропускаем.")

    if rows:
        typer.echo(tabulate.tabulate(rows, headers=headers, tablefmt='grid'))

    dump_last_matches(matches)

@app.command()
def copy(
  idx: int = typer.Argument(..., help='Номер записи из таблицы (от 1 до N)')
):
    '''
    Скопировать пароль в буфер обмена по номеру из последнего результата get.
    
    Сначала выполните команду get для отображения таблицы с номерами,
    затем используйте copy с нужным номером.
    
    Примеры:
      pas.py get github    # Показать таблицу с номерами
      pas.py copy 1        # Скопировать пароль из строки №1
      pas.py copy 3        # Скопировать пароль из строки №3
    '''
    if not LAST_MATCHES.exists():
        typer.echo('last_matches.json не существует.')
        return

    try:
        last_matches = json.loads(LAST_MATCHES.read_text('utf-8'))
    except json.JSONDecodeError:
        typer.echo('Ошибка чтения last_matches.json.')
        return

    if not last_matches:
        typer.echo('Нет последних матчей.')
        return

    if idx < 1 or idx > len(last_matches):
        typer.echo(f'Неверный индекс: {idx}. Доступно от 1 до {len(last_matches)}.')
        return

    if not STORE.exists():
        typer.echo('store.bin не существует.')
        return

    data = load_data()

    match = last_matches[idx - 1]
    if match in data:
        password = data[match].get("password", "")
        if password:
            pyperclip.copy(password)
            typer.echo(f"Пароль для {match} успешно скопирован в буфер обмена.")
        else:
            typer.echo(f'Пароль для {match} не найден')    
    else:
        typer.echo(f'Запись для {match} не найдена в store.json')

@app.command(name='del')
def delete(
    label: str = typer.Argument(..., help='Метка для удаления или "clear-all" для полной очистки')
):
    '''
     Удалить запись по метке или все записи.
    
    Требует подтверждения перед удалением для безопасности.
    Для полной очистки всех данных используйте "clear-all".
    
    Примеры:
      pas.py delete github-1      # Удалить конкретную запись
      pas.py delete "clear-all"   # Удалить все записи (в кавычках!)
    '''
    if not STORE.exists():
        typer.echo('Записей нет, файл не существует.')
        return
    
    data = load_data()
    
    if label.lower() == 'clear-all':
        if not typer.confirm('Удалить ВСЕ записи? Это действие необратимо!'):
            typer.echo('Очистка отменена.')
            return
        data.clear()
        save_data(data)
        typer.echo('Все данные были успешно удалены')
        return
    
    if label in data:
        if not typer.confirm('Удалить запись? Это действие необратимо!'):
            typer.echo('Очистка отменена.')
            return
        del data[label]
        typer.echo(f'Данные с меткой {label} были успешно удалены.')
        save_data(data)
    else:
        typer.echo(f'Метка "{label}" не найдена.')
        return

@app.command()
def edit(
    service: str = typer.Argument(..., help='Метка для изменения (например, "github(1)")'),
    username: str = typer.Option(None, '-u', '--username', help='Новое имя пользователя'),
    password: str = typer.Option(None, '-p', '--password', help='Новый пароль'),
    note: str = typer.Option(None, '--note', help='Новая заметка'),
    gen: bool = typer.Option(False, '--gen', help='Сгенерировать новый пароль'),
    length: int = typer.Option(16, '--length', help='Длина генерируемого пароля')
):
    '''
    Изменить существующую запись.
    
    Указывайте только те поля, которые хотите изменить. Остальные останутся без изменений.
    Показывает предварительный просмотр изменений и запрашивает подтверждение.
    
    Примеры:
      pas.py edit github-1 -u newuser              # Изменить только username
      pas.py edit github-1 -p newpass123           # Изменить только пароль
      pas.py edit github-1 --gen --length 24       # Сгенерировать новый пароль длиной 24
      pas.py edit github-1 --note "Новая заметка"  # Изменить только заметку
      pas.py edit github-1 -u user --gen           # Изменить username и сгенерировать пароль
    '''


    if not STORE.exists():
        typer.echo('Записей нет, файл не существует.')
        return

    data = load_data()
   
    if service not in data:
        typer.echo(f'Данные с меткой {service} не найдены.')
        return
    
    existing = data[service]
    
    if password is not None:
        if gen:
            typer.echo('Нельзя вводить одновременно -p И --gen \n ВЫХОД')
            return
    elif password is None and gen:
        password = secrets.token_urlsafe(length)
    elif password is None:
        password = existing.get("password", "")

    changes = []
    if username is not None:
        changes.append(f'username: {existing.get("username", "")} → {username}  ')
    if password != existing.get("password", ""):
        changes.append(f'password: {"*" * len(existing.get("password"))} → {"*" * len(password)}')
    if note is not None:
        changes.append(f'note: {existing.get("note", "")} → {note}')

    if not changes:
        typer.echo('Нет изменений для применения.')
        return

    typer.echo(f'\nПланируемые изменения для {service}:')
    for change in changes:
        typer.echo(f'  {change}')

    if not typer.confirm('\nПримененить изменения?'):
        typer.echo('Изменения отменены.')
        return

    updated_data = {
        'username': username if username is not None else existing.get("username", ""),
        'password': password,
        'note': note if note is not None else existing.get("note", "")
    }

    data[service] = updated_data
    save_data(data)
    typer.echo(f"Запись с меткой {service} была успешно изменена.")

@app.command()
def find(
    query: str = typer.Argument(..., help='Поисковый запрос (строка для поиска в полях)'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)')
):
    '''
    Поиск записей по подстроке в полях (username, password, note).
    
    Ищет подстроку во всех полях записи. Выводит результаты в таблице.
    
    Примеры:
      pas.py find "vova"               # Поиск "vova" во всех полях, пароли скрыты
      pas.py find "123" --show         # Поиск "123" с открытыми паролями
    '''
    if not STORE.exists():
        typer.echo('Записей нет, файл не существует.')
        return

    data = load_data()
    
    matches = []
    for key, inner_dict in data.items():
        for value in inner_dict.values():
            if query.lower() in str(value).lower(): 
                matches.append(key)
                break

    if not matches:
        typer.echo(f'Ничего не найдено по запросу "{query}".')
        return

    headers = ['№', 'Метка', "Логин", 'Пароль', 'Заметка']
    rows = []
    sorted_matches = sorted(matches)
    for i, match in enumerate(sorted_matches, start=1):
        inner_dict = data[match]
        username = inner_dict.get("username", "")
        password = inner_dict.get("password", "") if show else '******'
        note = inner_dict.get("note", "")
        rows.append([i, match, username, password, note])

    typer.echo(f'Найденные записи по запросу "{query}":')
    typer.echo(tabulate.tabulate(rows, headers=headers, tablefmt='grid'))
    dump_last_matches(sorted_matches)





@app.callback()
def main():
    """Инициализация сессии при запуске."""
    check_session()

if __name__ == '__main__':
    app()
#D:\kod\python\password_manager\password_new



