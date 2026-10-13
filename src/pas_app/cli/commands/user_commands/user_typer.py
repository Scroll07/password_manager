from functools import wraps
from typing import Callable

import typer
from pas_app.dependencies import get_keyring_tool

user_app = typer.Typer(
    help="User commands for account and backup vault management.",
    no_args_is_help=True
)

#imports
from pas_app.cli.commands.user_commands.master_cmd import change_master
from pas_app.cli.commands.user_commands.delete_user_cmd import delete_user

# add decorrator to check current_user and current_vault !!!!!!!!!!!!!!!!!!
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

user_app.command("set")(set_default_user)
user_app.command("change-master")(change_master)
user_app.command("delete")(delete_user)




