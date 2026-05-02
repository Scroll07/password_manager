import typer

from pas_app.services.file_utils import load_data
from pas_app.schemas.state import State
from pas_app.services.password import print_passwords


def find_command(
    ctx: typer.Context,
    query: str = typer.Argument(
        ..., help="Поисковый запрос (строка для поиска в полях)"
    ),
    show: bool = typer.Option(
        False, "--show", help="Показать пароли открытым текстом (по умолчанию скрыты)"
    ),
    exact: bool = typer.Option(
        False, "--exact", help="Искать точное совпадение (не подстроку)"
    ),
):
    """
    Поиск записей по подстроке в полях (username, password, note).

    Ищет подстроку во всех полях записи. Выводит результаты в таблице.

    Примеры:

      pas.py find "vova"               # Поиск "vova" во всех полях, пароли скрыты

      pas.py find "123" --show         # Поиск "123" с открытыми паролями
    """
    state: State = ctx.obj
    data = load_data(state=state)
    passwords = data.user_passwords

    if not data:
        typer.echo("Записей нет.")
        raise typer.Exit(code=0)

    result = []            
    for pas in passwords:
        data = pas.model_dump()
        if exact:
            if query in (data.values()):
                result.append(pas)
        else:
            if any(query in value for value in data.values()):
                result.append(pas) 
    

    if not result:
        typer.echo(f'Ничего не найдено по запросу "{query}".')
        raise typer.Exit(code=0)

    typer.echo(f'Найденные записи по запросу "{query}":')
    print_passwords(passwords=result, show=show)
