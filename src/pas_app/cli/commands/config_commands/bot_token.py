import time
import typer

from pas_app.adapters.console import clear_console
from pas_app.adapters.promts import exit_message_and_clear_console
from pas_app.config import UserConfig


def change_bot_token(config: UserConfig):
    while True:
        clear_console()
        text = """
            1 - View Bot token
            2 - Change Bot token 
            0 - Exit
        """
        config_data = config.load_config()

        choice = typer.prompt(text).strip()
        if choice == "0":
            exit_message_and_clear_console("Exit")

        elif choice == "1":
            typer.echo(f"Bot Token = {config_data.BOT_TOKEN}")
            time.sleep(2)
            continue

        elif choice == "2":
            user_promt = typer.prompt("Enter Bot Token: ").strip()
            config_data.BOT_TOKEN = user_promt
            config.save_config(config_data)
            continue

        else:
            typer.echo("Wrong Input")
            time.sleep(1)
            continue
        
