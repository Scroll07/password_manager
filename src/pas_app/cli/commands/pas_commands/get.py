import typer

from pas_app.services.password import print_passwords
from pas_app.dependencies import get_password_tool


def get_command(
    service: str = typer.Argument(
        ..., help='Service label (e.g., github) or "all"/"." for all entries'
    ),
    show: bool = typer.Option(
        False, "--show", help="Show passwords in plain text (default: hidden)"
    ),
    strict: bool = typer.Option(
        False, "--strict", help="Get passwords that strictly correspond (default: no strict)"
    ),
):
    """
    Display entry information by label or show all entries.

    Supports prefix matching - "github" will find github, github-1, github-2, etc.
    By default, passwords are hidden; use --show to display them.
    Use "all" or "." to display all stored entries.

    Examples:
        pas get github           # All entries starting with "github", passwords hidden

        pas get github --show    # Same, but with passwords shown

        pas get all              # All entries, passwords hidden
    """
    password_tool = get_password_tool()
    service = service.strip().lower()
    if service in ["all", "."]:
        passwords = password_tool.get_all_passwords()
    else:
        if strict:
            password = password_tool.get_one_password(service=service)
            passwords = [password] if password is not None else []
        else:
            passwords = password_tool.get_passwords_by_service(service=service)

    if not passwords:
        typer.echo("No entries found")
        return

    print_passwords(passwords=passwords, show=show)
