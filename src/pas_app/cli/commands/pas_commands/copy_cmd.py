
import json
import pyperclip
import typer

from pas_app.services.file_utils import load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password
from pas_app.config import LAST_MATCHES


def copy(
  ctx: typer.Context,
  
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

    state: State = ctx.obj
    data = load_data(state)

    match = last_matches[idx - 1]
    passwords = data.user_passwords
    for password in passwords:
        if password.service == match:
            pyperclip.copy(password.password)
            typer.echo(f"Пароль для {match} успешно скопирован в буфер обмена.")
            break
        else:
            typer.echo(f'Пароль для {match} не найден')    