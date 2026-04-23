from pas_app.schemas.state import State
import typer
import time

from pas_app.adapters.promts import exit_message_and_clear_console, clear_console
from pas_app.config import ConfigData, UserConfig


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
        if choice == 0:
            exit_message_and_clear_console("Выход")

        elif choice == 1:
            typer.echo(f"BASE_URL = {config_data.BASE_URL}")
            continue

        elif choice == 2:
            user_promt = typer.prompt("Введите Base url: ").strip()
            config_data.BASE_URL = user_promt
            config.save_config(config_data)
            continue

        elif choice == 3:
            config_data.BASE_URL = "http://localhost"
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
        if choice == 0:
            exit_message_and_clear_console("Выход")

        elif choice == 1:
            typer.echo(f"Bot Token = {config_data.BOT_TOKEN}")
            continue

        elif choice == 2:
            user_promt = typer.prompt("Введите Bot Token: ").strip()
            config_data.BOT_TOKEN = user_promt
            config.save_config(config_data)
            continue

        else:
            typer.echo("Wrong Input")
            time.sleep(1)
            continue
        

def configure_config(
    ctx: typer.Context,
    
    base_url: bool = typer.Option(False, "--url", help="Change Base url"),
    bot_token: bool = typer.Option(False, '--token', help="Change Telegram bot token"),
    default_user: bool = typer.Option(False, '--user', help="Change Current user"),
):
    state: State = ctx.obj
    config = state.config
    
    if base_url:
        change_base_url(config)
    elif bot_token:
        change_bot_token(config)
    elif default_user:
        #func get users -> возвращает существующих пользователей на этом пк
        pass