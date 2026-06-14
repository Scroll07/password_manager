





import time

import typer

from pas_app.adapters.console import clear_console
from pas_app.adapters.promts import exit_message_and_clear_console
from pas_app.config import ConfigFileData, UserConfig, get_config


def change_base_url(config: UserConfig):
    while True:
        clear_console()
        text = """
            1 - View Base URL
            2 - Change Base URL
            3 - Reset Base URL
            0 - Exit
        """
        config_data = config._refresh()

        choice = typer.prompt(text + "\nInput").strip()
        if choice == "0":
            exit_message_and_clear_console("Exit")

        elif choice == "1":
            typer.echo(f"BASE_URL = {config_data.local.BASE_URL}")
            time.sleep(2)
            continue

        elif choice == "2":
            user_promt = typer.prompt("Enter Base URL: ").strip()
            config_data.local.BASE_URL = user_promt
            config.save_config(config_data)
            continue

        elif choice == "3":
            config_data.local.BASE_URL = ConfigFileData.BASE_URL
            config.save_config(config_data)
            continue

        else:
            typer.echo("Wrong Input")
            time.sleep(1)
            continue
        
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