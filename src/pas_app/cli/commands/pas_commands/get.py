import tabulate
import typer

from pas_app.services.file_utils import dump_last_matches, load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password


def get_command(
    ctx: typer.Context,
    
    service: str = typer.Argument(..., help='Метка сервиса (например: github) или "all"/"." для всех записей'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)'),
    sort: str = typer.Option("service", '--sort', help="Введите категорию для сортировки. Существующие категории: 'service' - default, 'username', 'password', 'note'." )
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
    state: State = ctx.obj
    data = load_data(state=state)

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

    def sort_key(k):
        value = data[k].get(sort)
        if value is None:
            return ''
        return str(value).lower()
    
    try:
        if sort == 'service':
            sorted_matches = sorted(matches)
        else:
            sorted_matches = sorted(matches, key = sort_key, reverse=True)
    except Exception:
        typer.echo('Метка для сортировки не найдена, применена сортировка по service.')
        sorted_matches = sorted(matches)

    for i, match in enumerate(sorted_matches, start=1):
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

    # dump_last_matches(matches) NEED FIX FOR THIS FUNCTION