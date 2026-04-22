import secrets

import typer

from pas_app.services.file_utils import load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password


def edit_command(
    ctx: typer.Context,

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
    state: State = ctx.obj



    data = load_data(state)
    pas_to_change = None
    for pas in data.user_passwords:
        if pas.service == service:
            pas_to_change = pas
            break
    
    if pas_to_change is None:
        typer.echo("No such service in passwords")
        raise typer.Exit()
        
    
    
    if password is not None:
        if gen:
            typer.echo('Нельзя вводить одновременно -p И --gen \n ВЫХОД')
            return
    elif password is None and gen:
        password = secrets.token_urlsafe(length)
    elif password is None:
        password = pas_to_change.password

    

    changes = []
    if username is not None:
        changes.append(f'username: {pas_to_change.username} → {username}  ')
    if password != pas_to_change.password:
        changes.append(f'password: {"*" * len(existing.get("password", ''))} → {"*" * len(password)}') # type: ignore
    if note is not None:
        changes.append(f'note: {pas_to_change.note} → {note}')

    if not changes:
        typer.echo('Нет изменений для применения.')
        return

    typer.echo(f'\nПланируемые изменения для {service}:')
    for change in changes:
        typer.echo(f'  {change}')

    if not typer.confirm('\nПримененить изменения?'):
        typer.echo('Изменения отменены.')
        return

    
    pas_to_change.username = username if username is not None else pas_to_change.username
    pas_to_change.password = password
    pas_to_change.note = note
    
    save_data(state, data)
    typer.echo(f"Запись с меткой {service} была успешно изменена.")