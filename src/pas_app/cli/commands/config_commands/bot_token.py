


import time

import typer

from pas_app.adapters.console import clear_console
from pas_app.adapters.promts import exit_message_and_clear_console
from pas_app.config import UserConfig, get_config


def change_bot_token(config: UserConfig):
    while True:
        clear_console()
        text = """
            1 - View Bot token
            2 - Change Bot token 
            0 - Exit
        """
        config_data = config._refresh()

        choice = typer.prompt(text)
        if choice == "0":
            exit_message_and_clear_console("Exit")

        elif choice == "1":
            typer.echo(f"Bot Token = {config_data.local.BOT_TOKEN}")
            time.sleep(2)
            continue

        elif choice == "2":
            user_promt = typer.prompt("Enter Bot Token: ").strip()
            config_data.local.BOT_TOKEN = user_promt
            config.save_config(config_data)
            continue

        else:
            typer.echo("Wrong Input")
            time.sleep(1)
            continue
        
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