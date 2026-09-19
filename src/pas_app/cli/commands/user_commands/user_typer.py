import typer

user_app = typer.Typer(
    help="User commands for account and backup vault management.",
    no_args_is_help=True
)

#imports
from pas_app.cli.commands.config_commands.default_user import set_default_user
from pas_app.cli.commands.user_commands.master_cmd import change_master
from pas_app.cli.commands.user_commands.delete_user_cmd import delete_user

# add decorrator to check current_user and current_vault !!!!!!!!!!!!!!!!!!


user_app.command("set")(set_default_user)
user_app.command("change-master")(change_master)
user_app.command("delete")(delete_user)




