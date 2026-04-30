import tabulate
import typer

from pas_app.schemas.state import State
from pas_app.services.file_utils import load_data


def list_command(
    ctx: typer.Context
):
    """
    Показать список всех сохраненных меток сервисов.

    Выводит отсортированный список всех доступных записей.
    """
    state: State = ctx.obj
    
    data = load_data(state=state)
    passwords = data.user_passwords

    labels = [p.service for p in passwords]
    table = [[label] for label in labels]
    if not labels:
        typer.echo("Записей не найдено.")
        return
    else:
        typer.echo(tabulate.tabulate(table, headers=["Метки"], tablefmt="simple"))
