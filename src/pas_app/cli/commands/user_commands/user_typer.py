import typer

user_app = typer.Typer(
    help="""
API commands for account and backup vault management.

Use them to:

- register in the API;

- log into your account;

- upload backup vault to the server;

- download backup vault to another computer.

For more details, see:

  pas user <command> --help
""",
    no_args_is_help=True
)

#imports
from pas_app.cli.commands.user_commands.master_cmd import change_master
from pas_app.cli.commands.user_commands.delete_user_cmd import delete_user

#Maybe decorators

user_app.command("change-master")(change_master)
user_app.command("delete")(delete_user)




