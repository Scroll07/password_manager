import typer
import secrets

from pas_app.dependencies import get_password_tool
from pas_app.exceptions import EchoException

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
    note: str = typer.Option(
        '', "--note", help="Additional note or description"
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
    try:
        if password is not None:
            if gen:
                typer.echo("Cannot use both -p and --gen at the same time. EXIT")
                return
        elif password is None:
            password = secrets.token_urlsafe(length)
        elif password is None and not gen:
            typer.echo("You must specify either -p or --gen")
            return

        passwrod_tool = get_password_tool()
        passwrod_tool.add(
            service=service.strip().lower(),
            username=username,
            password=password,
            note=note
        )
        
        typer.echo("The new record was successfully created")
    except EchoException as e:
        typer.echo(e)
        raise typer.Exit(code=1)
    except Exception as e:
        typer.echo("Unexpected error")
        raise typer.Exit(code=1)
        