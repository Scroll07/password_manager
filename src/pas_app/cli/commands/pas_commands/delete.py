import typer

from pas_app.dependencies import get_password_tool


def delete_command(
    service: str = typer.Argument(
        ..., help='Label to delete or "clear-all" to delete all entries'
    ),
):
    """
    Delete an entry by label or clear all entries.

    Requires confirmation before deletion for security. To completely clear
    all data, use "clear-all" as the label.

    Examples:
        pas delete github-1      # Delete a specific entry

        pas delete "clear-all"   # Delete all entries (use quotes!)
    """
    password_tool = get_password_tool()
    service = service.strip().lower()

    if service == "clear-all":
        if not typer.confirm("Delete ALL entries? This action is irreversible!"):
            typer.echo("Deletion was canceled.")
            return
        password_tool.delete(service='', delete_all=True)
        typer.echo("All data was successfully deleted")
        raise typer.Exit(code=0)

    deleted = password_tool.delete(service=service)
    if deleted:
        typer.echo("Password was successfully deleted")
    else:
        typer.echo(f'Password "{service}" not found.')
