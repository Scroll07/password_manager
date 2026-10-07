from typing import Callable
from functools import wraps
import typer
import asyncio

from pas_app.dependencies import get_keyring_tool

from pas_app.cli.commands.vault_commands.create_cmd import create_vault_command
from pas_app.cli.commands.vault_commands.select_vault_cmd import select_current_vault

vault_app = typer.Typer(
    help="vault commands for vault management.",
    no_args_is_help=True
)

def create_vault_cmd(
    offline: bool = typer.Option(False, '--offline', '-o', help='Delete vault offline (Only from your device)')
):
    """
        offline (bool, optional): _description_. Defaults to typer.Option(False, '--offline', '-o', help='Delete vault offline (Only from your device)').
    """
    asyncio.run(create_vault_command(offline=offline))

def select_current_vault_cmd():
    """
    Dockstring here
    """
    select_current_vault()



# move this decorator somewhere to use globaly
# add decorator to check current_user before every command
def check_current_user_dec(func: Callable) -> Callable:
    @wraps(func)
    def wrapper(*args, **kwargs):
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        if keyring_data.current_user == '':
            # add here "set current user" func
            typer.echo("Current user doesnot selected")
            return
        # if keyring_data.current_vault == '':
        #     # add here "set current vault" func
        #     typer.echo("Current vault doesnot selected")
        #     return
        return func(*args, **kwargs)
    return wrapper
        