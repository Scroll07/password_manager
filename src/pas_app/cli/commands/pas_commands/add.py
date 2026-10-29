import time
import typer
import secrets

from pas_app.dependencies import get_password_tool, get_logger
from pas_app.exceptions import EchoException
from pas_app.adapters.promts import clear_console

logger = get_logger()

def add_command(
    service: str | None = typer.Argument(
        None, help="Service name (e.g., github, vk, yandex)"
    ),
    username: str | None = typer.Option(
        None, "-u", "--username", help="Username or email"
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
    is_interactive = (
            service is None
            and username is None
            and password is None
            and note is None
        )
    
    if is_interactive:
        service, username, password, note = interactive_add_wizard(length=length)
    else:
        if not service:
            typer.echo("Missing argument: 'SERVICE'.")
            raise typer.Exit(code=1)

        if not username:
            typer.echo("Missing option: '-u' / '--username'.")
            raise typer.Exit(code=1)

        if note is None:
            note = ""

        if password is not None and gen:
            logger.warning(
                "Conflict detected: both --password and --gen were supplied"
            )
            typer.echo("Cannot use both -p and --gen at the same time. EXIT")
            raise typer.Exit(code=1)

        if password is None:
            if gen:
                password = secrets.token_urlsafe(length)
            else:
                logger.warning("Missing password or --gen flag")
                typer.echo("You must specify either -p or --gen")
                raise typer.Exit(code=1)

    try:
        service_clean = service.strip().lower()

        password_tool = get_password_tool()
        password_tool.add(
            service=service_clean,
            username=username,
            password=password,
            note=note,
        )

        typer.echo(f"The new record for '{service_clean}' was successfully created")
        logger.info(f"Credential successfully created for service='{service_clean}'")
    except EchoException as e:
        logger.error(
            f"Business logic error while adding credential for '{service}': {e}"
        )
        typer.echo(e)
        raise typer.Exit(code=1)
    except Exception as e:
        logger.exception(
            f"Unexpected error while adding credential for '{service}': {e}"
        )
        typer.echo("Unexpected error")
        raise typer.Exit(code=1)
    

def interactive_add_wizard(length: int = 16) -> tuple[str, str, str, str]:
    typer.echo("\n--- Interactive Entry ---")

    service_val = ""
    username_val = ""
    password_val = ""
    note_val = ""

    while True:
        # Отображение текущего прогресса заполнения
        clear_console()
        pass_display = "*" * 8 if password_val else "[Will be generated]"
        typer.echo(
            f"\nCurrent entry:\n"
            f"  Service:  {service_val or '[Not set]'}\n"
            f"  Username: {username_val or '[Not set]'}\n"
            f"  Password: {pass_display}\n"
            f"  Note:     {note_val or '[None]'}\n"
        )

        # 1. Запрос сервиса
        if not service_val:
            user_input = typer.prompt("Enter service name").strip()
            if not user_input:
                typer.echo("Service cannot be empty.")
                time.sleep(2)
                continue
            service_val = user_input
            logger.debug(f"Wizard: service set to '{service_val}'")
            continue

        # 2. Запрос логина / email
        if not username_val:
            user_input = typer.prompt("Enter username or email").strip()
            if not user_input:
                typer.echo("Username cannot be empty.")
                time.sleep(2)
                continue
            username_val = user_input
            logger.debug(f"Wizard: username set for '{service_val}'")
            continue

        # 3. Запрос пароля (пустой ввод -> генерация)
        if not password_val:
            user_input = typer.prompt(
                "Enter password (press Enter to generate securely)",
                default="",
                show_default=False,
                hide_input=True,
            ).strip()

            if not user_input:
                password_val = secrets.token_urlsafe(length)
                typer.echo(f"Generated secure password: {password_val}")
                time.sleep(1)
            else:
                password_val = user_input
            continue

        # 4. Запрос примечания (опционально)
        if not note_val:
            note_val = typer.prompt(
                "Enter note (optional, press Enter to skip)",
                default="",
                show_default=False,
            ).strip()

        return service_val, username_val, password_val, note_val
