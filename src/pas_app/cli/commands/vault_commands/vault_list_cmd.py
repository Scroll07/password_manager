import typer

from pas_app.adapters.console import clear_console
from pas_app.dependencies import get_keyring_tool, get_logger
from pas_app.services.file_utils import get_VaultPringData, get_user_vault_files



logger = get_logger()

def vault_list():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    vaults = get_user_vault_files(username=username)
    if not vaults:
        typer.echo("You have no vaults to select.\nCreate a new one")
        raise typer.Exit(code=1)
    data = get_VaultPringData(vaults=vaults)
    
    
    clear_console()
    typer.echo(f"{username}'s Vaults:\n")
    for i, obj in enumerate(data, start=1):
        typer.echo(f'[{i}] - {obj.vault_name} ({obj.filename})')
    typer.echo("\n")