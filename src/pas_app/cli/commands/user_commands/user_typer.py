import typer

user_app = typer.Typer(
    help="User commands for account and backup vault management.",
    no_args_is_help=True
)

#imports
from pas_app.cli.commands.user_commands.master_cmd import change_master
from pas_app.cli.commands.user_commands.delete_user_cmd import delete_user

#Maybe decorators

user_app.command("change-master")(change_master)
user_app.command("delete")(delete_user)




