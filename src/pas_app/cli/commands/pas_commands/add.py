import typer
import secrets

from pas_app.services.file_utils import load_data, save_data
from pas_app.schemas.passwords import Password
from pas_app.config import get_config


def add_command(
    service: str = typer.Argument(
        ..., help="Service name (e.g., github, vk, yandex)"
    ),
    username: str = typer.Option(
        ..., "-u", "--username", help="Username or email"
    ),
    password: str | None = typer.Option(
        None, "-p", "--password", help="Password (if not specified, use --gen)"
    ),
    note: str | None = typer.Option(
        None, "--note", help="Additional note or description"
    ),
    gen: bool = typer.Option(False, "--gen", help="Generate a random password"),
    length: int = typer.Option(
        16, "--length", help="Length of generated password (default: 16)"
    ),
):
    """
    Add a new login and password entry.

    Stores a new service credential in the vault. You can either provide
    a password directly or generate a secure random one.

    Examples:
        pas add github -u myuser -p mypass123

        pas add vk -u user@email.com --gen --length 20

        pas add work-email -u john@company.com --gen --note "Work email"
    """
    config = get_config()

    if password is not None:
        if gen:
            typer.echo("Cannot use both -p and --gen at the same time. EXIT")
            return
    elif password is None:
        password = secrets.token_urlsafe(length)
    elif password is None and not gen:
        typer.echo("You must specify either -p or --gen")
        return

    data = load_data(config=config)

    labels = set(b.service for b in data.user_passwords)
    base = service.lower()
    candidate = base
    i = 1
    while candidate in labels:
        candidate = base + "-" + str(i)
        i += 1

    password_to_append = Password(
        service=candidate, username=username, password=password, note=note
    )
    data.user_passwords.append(password_to_append)

    save_data(vault_data=data)
