import typer

from pas_app.config import get_config, KeyringConfig


def reset_session():
    """
    Reset the current local session.

    This command clears the saved session data in the local config while
    keeping the current Base URL and bot token values.

    Examples:
        pas config reset-session
    """
    config = get_config()
    config_data = config._refresh()
    keyring = KeyringConfig()

    config_data.keyring = keyring
    
    config.save_config(data=config_data)
    
    typer.echo("The session was reset")
