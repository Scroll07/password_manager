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

from pas_app.cli.commands.api_commands.backups import backups
from pas_app.cli.commands.api_commands.register_cmd import register
from pas_app.cli.commands.api_commands.login_cmd import login
from pas_app.cli.commands.api_commands.upload_cmd import upload
from pas_app.cli.commands.api_commands.change_password import change_password
from pas_app.cli.commands.api_commands.backups_stats import backups_stats

from pas_app.services.password import check_session_dec
from pas_app.core.api import check_token_dec

upload = check_token_dec(upload)
backups = check_token_dec(backups)
change_password = check_token_dec(change_password)
backups_stats = check_token_dec(backups_stats)
# download = check_token_dec(download)
# delete = check_token_dec(delete)

upload = check_session_dec(upload)
backups = check_session_dec(backups)
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

def upload_command():
    """
    Upload backup vault to the server.

    Saves an encrypted copy of your local vault to the server.
    This backup can be restored on another computer if needed.

    Examples:
        pas api upload

    You will be prompted to enter a backup name for identification.
    """
    asyncio.run(upload())
    
def backups_command():
    """
    Manage your uploaded backups.

    Provides an interactive menu to view, rename, download, or delete
    your vault backups stored on the server. Choose an action from the menu.

    Examples:
        pas api backups

    Available actions:
    - View all backups
    - Download a backup
    - Rename a backup
    - Delete a backup
    """
    asyncio.run(backups())

def backup_stats_command():
    """
    Retrieve and display backup statistics for the user's account.

    Fetches backup statistics including total backup count,
    maximum, minimum, and average rows per backup, and weekly backup count.
    The statistics are presented in a formatted table.

    Example:
        pas api stats

    """
    asyncio.run(backups_stats())

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
cli_app.command("upload")(upload_command)
cli_app.command("backups")(backups_command)
cli_app.command("stats")(backup_stats_command)
cli_app.command("change-password")(change_password_command)

# cli_app.command("download")(download_command)
# cli_app.command("delete")(delete_command)
