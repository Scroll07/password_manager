import typer

user_app = typer.Typer(
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

#imports
from pas_app.cli.commands.user_commands.master_cmd import change_master
from pas_app.cli.commands.user_commands.delete_user_cmd import delete_user

#Maybe decorators

user_app.command("change-master")(change_master)
user_app.command("delete")(delete_user)




