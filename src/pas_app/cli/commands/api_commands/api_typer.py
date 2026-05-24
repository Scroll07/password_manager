import asyncio
import typer

cli_app = typer.Typer(
    help="""
API-команды для работы с аккаунтом и backup vault.

Используй их, чтобы:

- зарегистрироваться в API;

- войти в аккаунт;

- загрузить backup vault на сервер;

- скачать backup vault на другой компьютер.

Подробности смотри в:

  pas api <command> --help
""",
    no_args_is_help=True
)

from pas_app.cli.commands.api_commands.register_cmd import register
from pas_app.cli.commands.api_commands.login_cmd import login
from pas_app.cli.commands.api_commands.upload_cmd import upload
from pas_app.cli.commands.api_commands.download_cmd import download
from pas_app.cli.commands.api_commands.delete_cmd import delete

from pas_app.services.password import check_session_dec
from pas_app.core.api import check_token_dec

upload = check_token_dec(upload)
download = check_token_dec(download)
delete = check_token_dec(delete)

upload = check_session_dec(upload)
download = check_session_dec(download)
delete = check_session_dec(delete)





#Commands
def register_command():
    """
    Зарегистрировать API-аккаунт.

    Создаёт новый аккаунт для работы с удалённым vault backup.
    """

    asyncio.run(register())

def login_command():
    """
    Войти в API-аккаунт.

    Получает access token для последующих запросов.
    """
    asyncio.run(login())

def upload_command():
    """
    Загрузить backup vault на сервер.

    Сохраняет зашифрованный vault, чтобы можно было восстановить его на другом ПК.
    """
    asyncio.run(upload())
    
def download_command():
    """
    Скачать backup vault с сервера.

    Используется для восстановления паролей на другом устройстве.
    """
    asyncio.run(download())

def delete_command():
    """
    Удалить backup по айди
    """
    asyncio.run(delete())

cli_app.command("register")(register_command)
cli_app.command("login")(login_command)
cli_app.command("upload")(upload_command)
cli_app.command("download")(download_command)
cli_app.command("delete")(delete_command)
