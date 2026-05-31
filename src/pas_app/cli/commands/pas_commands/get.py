import typer

from pas_app.services.file_utils import load_data, dump_last_matches
from pas_app.services.password import print_passwords
from pas_app.config import get_config


def get_command(
    service: str = typer.Argument(
        ..., help='Service label (e.g., github) or "all"/"." for all entries'
    ),
    show: bool = typer.Option(
        False, "--show", help="Show passwords in plain text (default: hidden)"
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
    config = get_config()
    data = load_data(config=config)
    passwords = data.user_passwords

    if not data or not data.user_passwords:
        typer.echo("No entries found")
        return

    if service.lower() == "." or service.lower() == "all":
        passwords = sorted(passwords, key=lambda p: p.service)
    else:
        passwords = sorted(
            [p for p in passwords if p.service.lower().startswith(service.lower())],
            key=lambda p: p.service,
        )

    print_passwords(passwords=passwords, show=show)

    matches = [p.service for p in passwords]
    dump_last_matches(matches=matches)
