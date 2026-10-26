import typer
import asyncio

from pas_app.core.keyring import get_keyring_tool
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
from pas_app.cli.commands.vault_commands.vault_list_cmd import vault_list
from pas_app.cli.commands.vault_commands.vault_multi import vaults_actions
from pas_app.cli.commands.vault_commands.change_master_cmd import change_master
from pas_app.cli.commands.vault_commands.push_cmd import push_vault
from pas_app.cli.commands.vault_commands.pull_cmd import pull_vault
from pas_app.cli.commands.vault_commands.vault_sync_cmd import sync_vaults
from pas_app.cli.commands.vault_commands.vault_fetch_cmd import fetch


# Проверка Bearer token + refresh token
vaults_actions = check_token_dec(vaults_actions)
push_vault = check_token_dec(push_vault)
pull_vault = check_token_dec(pull_vault)
sync_vaults = check_token_dec(sync_vaults)
fetch = check_token_dec(fetch)


# Проверка на Current User is not None
change_master = check_current_values_dec(change_master)
create_vault_offline = check_current_values_dec(create_vault_offline)
create_vault_online = check_current_values_dec(create_vault_online)
push_vault = check_current_values_dec(push_vault)
pull_vault = check_current_values_dec(pull_vault)
select_current_vault = check_current_values_dec(select_current_vault)
vault_list = check_current_values_dec(vault_list)
sync_vaults = check_current_values_dec(sync_vaults)
fetch = check_current_values_dec(fetch)


def create_vault_cmd(
    offline: bool = typer.Option(False, '--offline', '-o', help='Creates vault offline (Only from your device)')
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
    
def vault_list_cmd():
    """
    Show a list of vaults for current user
    
    Examples:
        pas vault list
    """
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    vault_list(username=username)

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
    asyncio.run(vaults_actions())

def push_vault_cmd(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force push local changes to the server, overwriting higher or equal remote versions.",
    ),
):
    """
    Push local encrypted vault changes to the remote server.

    If the remote server contains a newer version, the push operation
    will fail by default to prevent data loss. Use --force to override.
    """
    asyncio.run(push_vault(force=force))


def pull_vault_cmd(
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force pull from the server even if local version is newer.",
    ),
    new: bool = typer.Option(
        True,
        "--new/--overwrite",
        "-n/-o",
        help="Save downloaded vault to a new versioned file (default). Use --overwrite (-o) to replace the existing local file.",
    ),
):
    """
    Pull and download the latest encrypted vault from the server.

    By default, the vault is safely pulled into a new separate versioned
    file (e.g., <name>_v<version>.json) to prevent accidental loss of local data.
    Use --overwrite (-o) if you explicitly want to update the existing local file.
    """
    asyncio.run(
        pull_vault(
            force=force,
            create_new_file=new,
        )
    )

def sync_vaults_cmd():
    """
    Synchronize vaults between local storage and the remote server.

    Performs bidirectional synchronization: downloads newer or missing vaults
    from the server (pull) and uploads locally created or modified vaults
    after verifying credentials (push).

    Examples:
        pas vault sync
    """
    asyncio.run(sync_vaults())

def fetch_vaults_cmd():
    """
    Fetch remote vault metadata and inspect synchronization status.

    Compares local vaults against the remote server without applying changes,
    prompting for passwords, or modifying local files. Displays a summary of
    vaults requiring pull, push, or already up to date.

    Examples:
        pas vault fetch
    """
    asyncio.run(fetch())


vault_app.command('create')(create_vault_cmd)
vault_app.command('list')(vault_list_cmd)
vault_app.command('set')(select_current_vault_cmd)
vault_app.command('actions')(vaults_actions_cmd)
vault_app.command('change-master')(change_master_cmd)
vault_app.command('fetch')(fetch_vaults_cmd)
vault_app.command('push')(push_vault_cmd)
vault_app.command('pull')(pull_vault_cmd)
vault_app.command('sync')(sync_vaults_cmd)
