from typing import Callable
from functools import wraps
import typer

from pas_app.dependencies import get_keyring_tool

vault_app = typer.Typer(
    help="vault commands for vault management.",
    no_args_is_help=True
)

# add decorator to check current_user before every command
def check_current_values_dec(func: Callable) -> Callable:
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
        