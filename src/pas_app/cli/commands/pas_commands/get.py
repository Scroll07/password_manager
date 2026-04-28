import tabulate
import typer

from pas_app.services.file_utils import dump_last_matches, load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password


def get_command(
    ctx: typer.Context,
    
    service: str = typer.Argument(..., help='Метка сервиса (например: github) или "all"/"." для всех записей'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)'),
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
    '''
    state: State = ctx.obj
    data = load_data(state=state)
    passwords = data.user_passwords

    if not data or not data.user_passwords:
        typer.echo('Записей нет')
        return


    if service.lower() == '.' or service.lower() == 'all':
        passwords = sorted(passwords, key=lambda p: p.service)
    else:
        passwords = sorted([p for p in passwords if p.service.lower().startswith(service.lower())], key=lambda p: p.service)
    
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
            typer.Exit(code=1)

        
    if rows:
        typer.echo(tabulate.tabulate(rows, headers=headers, tablefmt='grid'))

    # dump_last_matches(matches) NEED FIX FOR THIS FUNCTION