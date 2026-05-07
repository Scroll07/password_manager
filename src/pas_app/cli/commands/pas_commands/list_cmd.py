import tabulate
import typer

from pas_app.services.file_utils import load_data
from pas_app.config import config


def list_command(
):
    """
    Показать список всех сохраненных меток сервисов.

    Выводит отсортированный список всех доступных записей.
    """
    
    data = load_data(config=config)
    passwords = data.user_passwords

    labels = [p.service for p in passwords]
    table = [[label] for label in labels]
    if not labels:
        typer.echo("Записей не найдено.")
        return
    else:
        typer.echo(tabulate.tabulate(table, headers=["Метки"], tablefmt="simple"))
