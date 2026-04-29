import tabulate
import typer

from pas_app.services.file_utils import dump_last_matches, load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password
from pas_app.services.password import print_passwords


def find_command(
    ctx: typer.Context,
    
    query: str = typer.Argument(..., help='Поисковый запрос (строка для поиска в полях)'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)'),
    exact: bool = typer.Option(False, '--exact', help='Искать точное совпадение (не подстроку)'),
):
    '''
    Поиск записей по подстроке в полях (username, password, note).
    
    Ищет подстроку во всех полях записи. Выводит результаты в таблице.
    
    Примеры:

      pas.py find "vova"               # Поиск "vova" во всех полях, пароли скрыты

      pas.py find "123" --show         # Поиск "123" с открытыми паролями
    '''
    state: State = ctx.obj
    data = load_data(state=state)
    passwords = data.user_passwords
    
    if not data:
        typer.echo('Записей нет.')
        raise typer.Exit(code=1)
        

    def matches_values(value: str) -> bool:
        val_lower = str(value).lower()
        query_lower = query.lower()
        return query_lower == val_lower if exact else query_lower in val_lower
    
    try:
        passwords = [
            key for key, inner_dict in data.items()
            if any(matches_values(value) for value in inner_dict.values())
        ]
                
    except Exception as e:
        typer.echo(f'Ошибка при поиске: {str(e)}. Проверьте структуру данных.')
        raise typer.Exit(code=1)
    
    if not passwords:
        typer.echo(f'Ничего не найдено по запросу "{query}".')
        raise typer.Exit(code=1)



    typer.echo(f'Найденные записи по запросу "{query}":')
    print_passwords()
