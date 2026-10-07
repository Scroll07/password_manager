import asyncio
import typer

cli_app = typer.Typer(
    help="""
API commands for account and backup vault management.

Use them to:

- register in the API;

- log into your account;

- upload backup vault to the server;

- download backup vault to another computer.

For more details, see:

  pas api <command> --help
""",
    no_args_is_help=True
)

from pas_app.cli.commands.api_commands.register_cmd import register
from pas_app.cli.commands.api_commands.login_cmd import login
from pas_app.cli.commands.api_commands.change_password import change_password

from pas_app.services.password import check_session_dec
from pas_app.core.api import check_token_dec

# upload = check_token_dec(upload)
# change_password = check_token_dec(change_password)
# backups_stats = check_token_dec(backups_stats)

# download = check_token_dec(download)
# delete = check_token_dec(delete)

# download = check_session_dec(download)
# delete = check_session_dec(delete)





#Commands
def register_command():
    """
    Register a new API account.

    Creates a new account for working with remote vault backup storage.
    You will be prompted to enter a username and password for registration.

    Examples:
        pas api register

    After successful registration, a local vault will be created.
    """

    asyncio.run(register())

def login_command():
    """
    Log into an existing API account.

    Authenticates with the API and obtains access tokens for subsequent
    requests. Tokens are securely stored in the local configuration.

    Examples:
        pas api login

    You will be prompted to enter your username and password.
    """
    asyncio.run(login())



def change_password_command():
    """
    Change API account password.

    Updates the password for your API account while keeping backups
    and other account data intact.

    Examples:
        pas api change-password

    You will be prompted to enter a new password in a secure input window.
    """
    asyncio.run(change_password())
    

cli_app.command("register")(register_command)
cli_app.command("login")(login_command)
cli_app.command("change-password")(change_password_command)
