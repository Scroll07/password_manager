import typer

from pas_app.dependencies import get_password_tool
from pas_app.services.password import print_passwords


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
    password_tool = get_password_tool()
    passwords = password_tool.find(query=query, exact=exact)

    if len(passwords) == 0:
        typer.echo(f'Nothing found for query "{query}".')
    else:
        typer.echo(f'Found entries for query "{query}":')
        print_passwords(passwords=passwords, show=show)
        
