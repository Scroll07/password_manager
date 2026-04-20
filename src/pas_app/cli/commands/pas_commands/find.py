import tabulate
import typer

from pas_app.config import STORE
from services.password import dump_last_matches, load_data


def find_command(
    query: str = typer.Argument(..., help='Поисковый запрос (строка для поиска в полях)'),
    show: bool = typer.Option(False, '--show', help='Показать пароли открытым текстом (по умолчанию скрыты)'),
    exact: bool = typer.Option(False, '--exact', help='Искать точное совпадение (не подстроку)'),
    sort: str = typer.Option('service', '--sort', help="Введите категорию для сортировки. Существующие категории: 'service' - default, 'username', 'password', 'note'." )
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
        matches: list[str] = [key for key, inner_dict in data.items()
                if any(matches_values(value) for value in inner_dict.values())]
    except Exception as e:
        typer.echo(f'Ошибка при поиске: {str(e)}. Проверьте структуру данных.')
        return
    
    if not matches:
        typer.echo(f'Ничего не найдено по запросу "{query}".')
        return

    def sort_key(k):
        value = data[k].get(sort)
        if value is None:
            return ''
        return str(value).lower()

    headers = ['№', 'Метка', "Логин", 'Пароль', 'Заметка']
    rows = []
    try:
        if sort == 'service':
            sorted_matches = sorted(matches)
        else:
            sorted_matches = sorted(matches, key = sort_key, reverse=True)
    except Exception:
        typer.echo('Метка для сортировки не найдена, применена сортировка по service.')
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