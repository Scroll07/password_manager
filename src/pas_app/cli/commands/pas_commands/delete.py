import typer


from pas_app.services.file_utils import load_data, save_data
from pas_app.config import get_config


def delete_command(
    label: str = typer.Argument(
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
    config = get_config()
    data = load_data(config=config)

    if label.lower() == "clear-all":
        if not typer.confirm("Delete ALL entries? This action is irreversible!"):
            typer.echo("Deletion was canceled.")
            return
        data.user_passwords = []
        save_data(vault_data=data)
        typer.echo("All data was successfully deleted")
        raise typer.Exit(code=0)

    for pas in data.user_passwords:
        if label.strip() == pas.service.strip():
            if not typer.confirm("Delete this entry? This action is irreversible!"):
                typer.echo("Deletion was canceled.")
                typer.Exit(code=0)
            data.user_passwords.remove(pas)
            typer.echo(f"Entry with label {label} was successfully deleted.")
            save_data(vault_data=data)
            raise typer.Exit(code=0)

    typer.echo(f'Label "{label}" not found.')
    raise typer.Exit(code=0)
