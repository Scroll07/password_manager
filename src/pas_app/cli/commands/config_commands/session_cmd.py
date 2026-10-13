import typer

from pas_app.dependencies import get_keyring_tool


def reset_session():
    """
    Reset the current local session.

    This command clears the saved session data in the local config while
    keeping the current Base URL and bot token values.

    Examples:
        pas config reset
    """
    keyring = get_keyring_tool() 
    keyring.
    
    typer.echo("The config was reset")
