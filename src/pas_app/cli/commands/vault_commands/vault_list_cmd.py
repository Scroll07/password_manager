from tabulate import tabulate
import typer

from pas_app.services.file_utils import get_VaultPringData, get_user_vault_files


def vault_list(username: str):
    vaults = get_user_vault_files(username=username)
    if not vaults:
        typer.echo("You have no vaults to select.\nCreate a new one")
        raise typer.Exit(code=1)
    data = get_VaultPringData(vaults=vaults)
    
    table_data = [
        [f'[{i}]', obj.vault_name, f"v1.{obj.version}", obj.filename]
        for i, obj in enumerate(data, start=1)
    ]

    headers = [" №", "Vault Name", "Version", "File"]

    rendered_table = tabulate(table_data, headers=headers, tablefmt="simple")

    typer.echo(f"\n{username}'s Vaults:\n")
    typer.echo(rendered_table)
    typer.echo("\n")