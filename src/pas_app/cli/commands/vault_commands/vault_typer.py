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
from pas_app.cli.commands.vault_commands.create_cmd import create_vault_offline, create_vault_online
from pas_app.cli.commands.vault_commands.select_vault_cmd import select_current_vault
from pas_app.cli.commands.vault_commands.vault_multi import vaults_acions
from pas_app.cli.commands.vault_commands.change_master_cmd import change_master


# Проверка Bearer token + refresh token
vaults = check_token_dec(vaults_acions)

# Проверка на Current User is not None
change_master = check_current_values_dec(change_master)
create_vault_offline = check_current_values_dec(create_vault_offline)
create_vault_online = check_current_values_dec(create_vault_online)




def create_vault_cmd(
    offline: bool = typer.Option(False, '--offline', '-o', help='Delete vault offline (Only from your device)')
):
    """
    Create a new local vault for storing passwords.

    A vault is a local encrypted storage that holds your passwords.
    Use --offline to create a vault that exists only on your device
    without connecting to the remote API.

    Examples:
        pas vault create           # Create vault with API sync

        pas vault create --offline # Create local-only vault
    """
    if offline:
        create_vault_offline()
    else:
        asyncio.run(create_vault_online())
        

def select_current_vault_cmd():
    """
    Select a vault to work with.

    If you have multiple vaults, this command lets you switch between them.
    The selected vault will be used for all password operations.

    Examples:
        pas vault select
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


def vaults_actions_cmd():
    """
    Perform bulk actions on vaults (rename, delete, etc.).

    Opens an interactive menu for managing vault properties
    such as renaming, deleting, or changing vault settings.

    Examples:
        pas vault actions
    """
    asyncio.run(vaults_acions())
        

vault_app.command('create')(create_vault_cmd)
vault_app.command('set')(select_current_vault_cmd)
vault_app.command('actions')(vaults_actions_cmd)
vault_app.command('change-master')(change_master_cmd)
