import pyperclip
import typer

from pas_app.dependencies import get_password_tool

def copy(
    service: str = typer.Argument(..., help="Service name of password to copy"),
):
    """
    Copy password to clipboard.
    """
    service = service.strip().lower()
    password_tool = get_password_tool()
    password = password_tool.get_one_password(service=service)
    if password is None:
        typer.echo(f"Password with service {service} was not found")
    else:
        pyperclip.copy(password.password)
        typer.echo(f"Password for {service} successfully copied to clipboard.")
