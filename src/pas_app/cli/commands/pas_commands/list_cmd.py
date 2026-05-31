import tabulate
import typer

from pas_app.services.file_utils import load_data
from pas_app.config import get_config


def list_command(
):
    """
    List all saved service labels in the vault.

    Displays a sorted list of all available entries without showing passwords.
    Useful for quickly viewing what services are stored.

    Examples:
        pas list
    """
    config = get_config()
    data = load_data(config=config)
    passwords = data.user_passwords

    labels = [p.service for p in passwords]
    table = [[label] for label in labels]
    if not labels:
        typer.echo("No entries found.")
        return
    else:
        typer.echo(tabulate.tabulate(table, headers=["Labels"], tablefmt="simple"))
