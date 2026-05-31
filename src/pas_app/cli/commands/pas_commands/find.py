import typer

from pas_app.services.file_utils import load_data
from pas_app.services.password import print_passwords
from pas_app.config import get_config


def find_command(
    query: str = typer.Argument(
        ..., help="Search query (string to search in fields)"
    ),
    show: bool = typer.Option(
        False, "--show", help="Show passwords in plain text (default: hidden)"
    ),
    exact: bool = typer.Option(
        False, "--exact", help="Search for exact match (not substring)"
    ),
):
    """
    Search entries by substring in fields (username, password, note).

    Searches all fields of each entry and displays matching results in a table.
    By default, passwords are hidden; use --show to display them.

    Examples:
        pas find "vova"               # Search "vova" in all fields, passwords hidden

        pas find "123" --show         # Search "123" with passwords shown

        pas find "github" --exact     # Exact match search
    """
    config = get_config()
    data = load_data(config=config)
    passwords = data.user_passwords

    if not data:
        typer.echo("No entries found.")
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
        typer.echo(f'Nothing found for query "{query}".')
        raise typer.Exit(code=0)

    typer.echo(f'Found entries for query "{query}":')
    print_passwords(passwords=result, show=show)
