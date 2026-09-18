import json
import typer

from pas_app.dependencies import get_password_tool

def export_command():
    """
    Export vault data to a JSON file.

    Creates a backup file with all your stored credentials. 

    Examples:
        pas export
    """

    if not typer.confirm("Export may expose sensitive data. Continue?"):
        typer.echo("Export was canceled. EXIT")
        return

    password_tool = get_password_tool()
    path = password_tool.export_passwords()
    typer.echo(f"Data exported to {path}")


