
import typer

from pas_app.adapters.console import clear_console
from pas_app.services.file_utils import (
    get_VaultPringData,
    get_vault_username_folders,
    get_vault_usernames_with_vault,
    get_user_vault_files
)




def user_list(
    users_with_created_vaults: bool,
    show_user_vaults: bool
):
    if users_with_created_vaults:
        usernames = get_vault_usernames_with_vault()
    else:
        usernames = get_vault_username_folders()
    
    if not usernames:
        typer.echo("There is no existing user folders on this device")
        raise typer.Exit(code=0)
    
    clear_console()
    if show_user_vaults:
        for username in usernames:
            vaults = get_user_vault_files(username=username)
            data = get_VaultPringData(vaults=vaults)
    
            typer.echo(f"\n-- {username}")
            for obj in data:
                typer.echo(f'------ {obj.vault_name} ({obj.filename})')
    else:
        for username in usernames:
            typer.echo(f"--{username}")
            
    typer.echo("\n")