import secrets

import typer

from pas_app.config import STORE
from pas_app.core.services import load_data, save_data


def edit_command(
    service: str = typer.Argument(..., help='Метка для изменения (например, "github(1)")'),
    username: str | None = typer.Option(None, '-u', '--username', help='Новое имя пользователя'),
    password: str | None = typer.Option(None, '-p', '--password', help='Новый пароль'),
    note: str | None = typer.Option(None, '--note', help='Новая заметка'),
    gen: bool | None = typer.Option(False, '--gen', help='Сгенерировать новый пароль'),
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
    
    existing: dict = data[service]
    
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
        changes.append(f'password: {"*" * len(existing.get("password", ''))} → {"*" * len(password)}') # type: ignore
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