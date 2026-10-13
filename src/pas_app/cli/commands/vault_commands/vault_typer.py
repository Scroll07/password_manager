import typer
import asyncio

from pas_app.decorators import (
    check_current_values_dec,
    check_token_dec
)




vault_app = typer.Typer(
    help="vault commands for vault management.",
    no_args_is_help=True
)

# Imports
from pas_app.cli.commands.vault_commands.create_cmd import create_vault_command
from pas_app.cli.commands.vault_commands.select_vault_cmd import select_current_vault
from pas_app.cli.commands.vault_commands.vault_multi import vaults
from pas_app.cli.commands.vault_commands.change_master_cmd import change_master
 

# Проверка Bearer token + refresh token
vaults = check_token_dec(vaults)

# Проверка на Current User is not None
change_master = check_current_values_dec(change_master)





def create_vault_cmd(
    offline: bool = typer.Option(False, '--offline', '-o', help='Delete vault offline (Only from your device)')
):
    """
        offline (bool, optional): _description_. Defaults to typer.Option(False, '--offline', '-o', help='Delete vault offline (Only from your device)').
    """
    if offline:
        ...
    else:
        asyncio.run(create_vault_command(offline=offline))

def select_current_vault_cmd():
    """
    Dockstring here
    """
    select_current_vault()

def change_master_cmd():
    """
    Change the master password for local vault.

    The command requires entering the current password and a new password.
    The operation is irreversible and will re-encrypt all stored passwords
    with the new master password.

    Examples:
        pas vault change-master

    """
    change_master()


        