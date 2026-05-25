import typer
import time

from pas_app.adapters.promts import exit_message_and_clear_console, clear_console, choose_default_user
from pas_app.services.file_utils import get_vault_usernames
from pas_app.config import UserConfig
from pas_app.config import config

def change_base_url(config: UserConfig):
    while True:
        clear_console()
        text = """
            1 - Посмотреть Base url
            2 - Изменить Base url
            3 - Сбросить Base url
            0 - Выйти
        """
        config_data = config._refresh()

        choice = typer.prompt(text)
        if choice == "0":
            exit_message_and_clear_console("Выход")

        elif choice == "1":
            typer.echo(f"BASE_URL = {config_data.local.BASE_URL}")
            continue

        elif choice == "2":
            user_promt = typer.prompt("Введите Base url: ").strip()
            config_data.local.BASE_URL = user_promt
            config.save_config(config_data)
            continue

        elif choice == "3":
            config_data.local.BASE_URL = "http://localhost"
            config.save_config(config_data)
            continue

        else:
            typer.echo("Wrong Input")
            time.sleep(1)
            continue


def change_bot_token(config: UserConfig):
    while True:
        clear_console()
        text = """
            1 - Посмотреть Bot token
            2 - Изменить Bot token 
            0 - Выйти
        """
        config_data = config._refresh()

        choice = typer.prompt(text)
        if choice == "0":
            exit_message_and_clear_console("Выход")

        elif choice == "1":
            typer.echo(f"Bot Token = {config_data.local.BOT_TOKEN}")
            continue

        elif choice == "2":
            user_promt = typer.prompt("Введите Bot Token: ").strip()
            config_data.local.BOT_TOKEN = user_promt
            config.save_config(config_data)
            continue

        else:
            typer.echo("Wrong Input")
            time.sleep(1)
            continue


def configure_config(
    base_url: bool = typer.Option(False, "--url", help="Change Base url"),
    bot_token: bool = typer.Option(False, "--token", help="Change Telegram bot token"),
    default_user: bool = typer.Option(False, "--user", help="Change Default user"),
):
    """
    Configure application settings interactively.

    Allows changing specific configuration parameters one by one.
    When an option is specified, the user will be prompted to enter a new value.


    Options:
      --url       Change the base URL for API requests
      --token     Change the Telegram bot authentication token
      --user      Change the default user identifier
    """

    if base_url:
        change_base_url(config)
    elif bot_token:
        change_bot_token(config)
    elif default_user:
        usernames = get_vault_usernames()
        username = choose_default_user(usernames=usernames)
        config_data = config._refresh()
        config_data.local.default_user = username
        config.save_config(data=config_data)
    else:
        typer.echo("No options to configure")
