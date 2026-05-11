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

from pas_app.cli.commands.api_commands.register_cmd import register_command
from pas_app.cli.commands.api_commands.login_cmd import login_command
from pas_app.cli.commands.api_commands.upload_cmd import upload_command
from pas_app.cli.commands.api_commands.download_cmd import download_command
from pas_app.cli.commands.api_commands.delete_cmd import delete_command

from pas_app.services.password import check_session_dec

upload_command = check_session_dec(upload_command)
download_command = check_session_dec(download_command)


cli_app.command("register")(register_command)
cli_app.command("login")(login_command)
cli_app.command("upload")(upload_command)
cli_app.command("download")(download_command)
cli_app.command("delete")(delete_command)
