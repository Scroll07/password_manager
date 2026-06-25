import typer

from pas_app.services.file_utils import load_data, dump_last_matches
from pas_app.services.password import print_passwords
from pas_app.config import get_config


def check_password_strength_command(
    service: str = typer.Option(
        "", help='Service label (e.g., github)'
    ),
    show: bool = typer.Option(
        False, "--show", help="Show passwords in plain text (default: hidden)"
    ),
):
    """
    """
    config = get_config()
    data = load_data(config=config)
    passwords = data.user_passwords

    if not data or not data.user_passwords:
        typer.echo("No entries found")
        return

    if service:
        for pas in passwords:
            if pas.service.strip() == service.strip():
                passwords = [pas]
    else:
        passwords = sorted(
            [p for p in passwords if p.service.lower().startswith(service.lower())],
            key=lambda p: p.service,
        )

    print_passwords(passwords=passwords, show=show, check=True)
