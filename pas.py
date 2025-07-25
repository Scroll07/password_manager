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
import csv

BASE_DIR = Path(__file__).resolve().parent
STORE = BASE_DIR / 'store.bin'
LAST_MATCHES = BASE_DIR / 'last_matches.json'
SESSION_FILE = BASE_DIR / 'session.json'
SALT_FILE = BASE_DIR / 'salt_file.bin'

session_key = None
session_start_time = None
SESSION_TIMEOUT = 300

app = typer.Typer(help="""
Менеджер паролей: безопасное хранение логинов и паролей.

Основной рабочий процесс:

  1. Добавьте запись:
     pas add <сервис> -u <логин> --gen

  2. Просмотрите список:
     pas list

  3. Найдите нужную запись:
     pas get <метка_или_начало>

  4. Скопируйте пароль:
     pas copy <номер_из_таблицы>

Дополнительные команды:

  - Изменить запись:
    pas edit <метка> [опции]

  - Поиск по полям:
    pas find <запрос>

  - Удалить запись:
    pas del <метка>          (или 'clear-all' для полной очистки)

  - Сбросить сессию:
    pas reset-session

 - Экспорт данных:
    pas export <файл> [--format json|csv] [--include-passwords]

  - Импорт данных:
    pas import <файл> [--format json|csv] [--overwrite]

Все данные надёжно шифруются в файле store.bin.
Для справки по любой команде используйте:
  pas <команда> --help
""",
no_args_is_help=True)

def gui_password_prompt():
    root = tk.Tk()
    root.withdraw()  
    password = simpledialog.askstring("Мастер-пароль", "Введите мастер пароль:", show='*')
    root.destroy()
    return password

def save_session():
    global session_key, session_start_time
    data = {
        'start_time': session_start_time,
        'key': base64.urlsafe_b64encode(session_key).decode('utf-8')
    }
    with open(SESSION_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f)

def check_session(force_prompt: bool = False):
    global session_key, session_start_time
    if not force_prompt and SESSION_FILE.exists():
        try:
            with open(SESSION_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                session_start_time = data['start_time']
                session_key = base64.urlsafe_b64decode(data['key'])
            if time.time() - session_start_time < SESSION_TIMEOUT:
                session_start_time = time.time()
                save_session()
                return session_key
        except (json.JSONDecodeError, KeyError, ValueError, base64.binascii.Error):
            pass


    master_password = gui_password_prompt()
    if not master_password:
        typer.echo('Ввод пароля отменен.')
        raise typer.Exit()
    
    try:
        key = get_master_key(master_password)
        if STORE.exists():
            encrypted = STORE.read_bytes()
            _ = decrypt_data(encrypted, key)
        session_key = key
        session_start_time = time.time()
        save_session()
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
    service: str = typer.Argument(..., help='Метка сервиса (например: github) или "all"/"." для всех записей'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)')
):
    '''
    Показать информацию о записях по метке или все записи.
    
    Поддерживает поиск по началу метки - "github" найдет github, github-1, github-2 и т.д.

    По умолчанию пароли скрыты символами ******, используйте --show для отображения.

    Для всех записей используйте "all" или ".".

    Примеры:

      pas.py get github           # Все записи, начинающиеся с "github", пароли скрыты

      pas.py get github --show    # То же, но с открытыми паролями

      pas.py get all              # Все записи, пароли скрыты

      pas.py get . --show         # Все записи с открытыми паролями
    '''
    if not STORE.exists():
        typer.echo('Записей нет')
        return

    data = load_data()

    if not data:
        typer.echo('Записей нет')
        return

    if service.lower() == '.' or service.lower() == 'all':
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
    
    Сначала выполните команду get для отображения таблицы с номерами, затем используйте copy с нужным номером.
    
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
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)'),
    exact: bool = typer.Option(False, '--exact', help='Искать точное совпадение (не подстроку)')
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
    if not data:
        typer.echo('Записей нет.')
        return

    def matches_values(value: str) -> bool:
        val_lower = str(value).lower()
        query_lower = query.lower()
        return query_lower == val_lower if exact else query_lower in val_lower

    try:
        matches = [key for key, inner_dict in data.items()
                if any(matches_values(value) for value in inner_dict.values())]
    except Exception as e:
        typer.echo(f'Ошибка при поиске: {str(e)}. Проверьте структуру данных.')
        return
    
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

@app.command()
def reset_session():
    '''Сбросить текущую сессию.'''
    global session_start_time, session_key
    session_key = None
    session_start_time = None
    if SESSION_FILE.exists():
        SESSION_FILE.unlink(missing_ok=True)
    typer.echo('Сессия сброшена.')

@app.command()
def export(
    filename: str = typer.Argument(..., help="Имя файла для экспорта (например, export.json)"),
    format: str = typer.Option("json", "--format", help="Формат: json или csv (по умолчанию: json)"),
    include_passwords: bool = typer.Option(False, "--include-passwords", help="Включить пароли в экспорт (опасно!)")
):
    '''
    Экспорт данных из store.bin в файл.

    Примеры:

      pas export my_export.json --format json --include-passwords

      pas export my_export.csv --format csv
    '''
    if not STORE.exists():
        typer.echo('Нет данных для экспорта.')
        return

    data = load_data()
    if not typer.confirm("Экспорт может раскрыть чувствительные данные. Продолжить?"):
        typer.echo("Экспорт отменен. ВЫХОД")
        return

    export_data = {}
    for label, entry in data.items():
        export_entry = {
            "username": entry.get("username", ""),
            "note": entry.get("note", "")
        }
        if include_passwords:
            export_entry["password"] = entry.get("password", "")
        export_data[label] = export_entry

    if format.lower() == "json":
        with open(filename, 'w', encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        typer.echo(f"данные экспортированы в {filename} (JSON)")
    elif format.lower() == 'csv':
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Метка", "Логин", "Пароль", "Заметка"])
            for label, entry in export_data.items():
                writer.writerow([label, entry.get("username", ""), entry.get("password", ""), entry.get("note", "")])
        typer.echo(f"Данные экспортированы в {filename} (CSV).")
    else:
        typer.echo("Неправильный формат, используйте JSON или CSV.")

@app.command(name='import_data')
def import_data(
    filename: str = typer.Argument(..., help="Имя файла для импорта (например, export.json)"),
    format: str = typer.Option("json", "--format", help="Формат: json или csv (по умолчанию: json)"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Перезаписать существующие метки")
):
    '''
     Импорт данных в store.bin из файла.

    Примеры:

      pas import my_export.json --format json --overwrite

      pas import my_export.csv --format csv
    '''
    if not Path(filename).exists():
        typer.echo(f'Файл {filename} не найден.')
        return
    if format.lower() == 'json':
        with open(filename, 'r', encoding='utf-8') as f:
            import_data = json.load(f) 
    elif format.lower() == "csv":
        import_data = {}
        with open(filename, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Пропустить заголовок
            for row in reader:
                if len(row) >= 4:
                    label, username, password, note = row[:4]
                    import_data[label] = {"username": username, "password": password, "note": note}
    else:
        typer.echo("Неподдерживаемый формат. Используйте json или csv.")
        return

    current_data = load_data()

    if not typer.confirm("Импорт может изменить существующие записи. Продолжить?"):
        typer.echo('Импорт отменен. ВЫХОД')
        return
    
    for label, entry in import_data.items():
        if label in current_data and not overwrite:
            typer.echo(f"Метка {label} уже существует. Пропускаем (Используйте --overwrite для замены).")
            continue
        current_data[label] = entry

    save_data(current_data)
    typer.echo(f'Данные успешно импортированы из {filename}')

@app.callback()
def main():
    """Инициализация сессии при запуске."""
    check_session()

if __name__ == '__main__':
    app()
#cd D:\kod\python\password_manager\password_new
#python install setyp.py
#.\scripts\activate.ps1


