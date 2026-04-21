import tabulate
import typer

from pas_app.services.password import load_data


def list_command():
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