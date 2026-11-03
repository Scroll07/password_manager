import typer
from pas_app.dependencies import (
    get_config,
    get_keyring_tool
)

config_app = typer.Typer(
    help="Configuration commands for managing local CLI settings.",
    no_args_is_help=True
)

#imports
from pas_app.cli.commands.config_commands.bot_token import change_bot_token
from pas_app.cli.commands.config_commands.url import change_base_url

#Maybe decorators

def url_cmd():
    """
    Manage the local API base URL.

    This command allows you to view, change, or reset the locally stored
    Base URL used by the CLI for server requests.

    Examples:
        pas config url
    """
    config = get_config()
    change_base_url(config=config)

def token_cmd():
    """
    Manage the local bot token.

    This command allows you to view or change the bot token stored in the
    local CLI configuration.

    Examples:
        pas config token
    """
    config = get_config()
    change_bot_token(config=config)

def reset_session():
    """
    Reset the current local session.

    This command clears the saved session data in the local config while
    keeping the current Base URL and bot token values.

    Examples:
        pas config reset
    """
    keyring = get_keyring_tool() 
    keyring.reset_keyring_values()
    
    typer.echo("The session was reset")
    
    
config_app.command("url")(url_cmd)
config_app.command("token")(token_cmd)
config_app.command("reset")(reset_session)






