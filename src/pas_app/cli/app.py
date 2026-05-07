import typer

from pas_app.services.password import check_session_dec

from pas_app.cli.commands.pas_commands.add import add_command
from pas_app.cli.commands.pas_commands.list_cmd import list_command
from pas_app.cli.commands.pas_commands.get import get_command
from pas_app.cli.commands.pas_commands.delete import delete_command
from pas_app.cli.commands.pas_commands.find import find_command
from pas_app.cli.commands.pas_commands.edit import edit_command
from pas_app.cli.commands.pas_commands.master_cmd import change_master
from pas_app.cli.commands.pas_commands.session_cmd import reset_session
from pas_app.cli.commands.pas_commands.import_cmd import import_data
from pas_app.cli.commands.pas_commands.export_cmd import export_command
from pas_app.cli.commands.pas_commands.others_cmd import get_path
from pas_app.cli.commands.pas_commands.copy_cmd import copy
from pas_app.cli.commands.pas_commands.create_secret_key import create_password_command
from pas_app.cli.commands.pas_commands.configure_config import configure_config

from pas_app.cli.commands.api_commands import cli_app


from pas_app.config import config


app = typer.Typer(
    help="""
CLI-менеджер паролей с локальным шифрованием vault.

Быстрый старт:
  pas add github -u mylogin --gen
  pas list
  pas get github
  pas copy 1

Основные команды:
  add             Добавить запись
  list            Показать все записи
  get             Показать запись по метке
  copy            Скопировать пароль по номеру
  edit            Изменить запись
  del             Удалить запись
  find            Поиск по vault

Сессия и безопасность:
  reset-session   Сбросить текущую сессию
  change-master   Сменить мастер-пароль

Импорт и экспорт:
  export          Экспорт vault в файл
  import          Импорт данных из файла

Настройки и утилиты:
  config          Настройки приложения
  create-key      Генератор паролей
  get-path        Показать путь к файлам vault

API и backup:
  api register    Создать API-аккаунт
  api login       Войти в API
  api upload      Загрузить backup vault
  api download    Скачать backup vault

Подсказки:
  pas <command> --help
  pas api --help
""",
    no_args_is_help=True,
)
#Check session Decorator
add_command = check_session_dec(add_command)
list_command = check_session_dec(list_command)
get_command = check_session_dec(get_command)
copy_command = check_session_dec(copy)
delete_command = check_session_dec(delete_command)
find_command = check_session_dec(find_command)
edit_command = check_session_dec(edit_command)
export_command = check_session_dec(export_command)
import_command = check_session_dec(import_data)


#Base commands
app.command("add")(add_command)
app.command("list")(list_command)
app.command("get")(get_command)
app.command("copy")(copy_command)
app.command("del")(delete_command)
app.command("find")(find_command)
app.command("edit")(edit_command)
app.command("export")(export_command)
app.command("import")(import_command)
app.command("reset-session")(reset_session)
app.command("change-master")(change_master)
app.command("config")(configure_config)
app.command("get-path")(get_path)


# KEYS
app.command("create-key")(create_password_command)

# API
app.add_typer(cli_app, name="api")



@app.callback()
def main():
    """Инициализация сессии при запуске."""
    try:
        config.create_empty_config(current_user="unauthorized")
        # check_session()
    except Exception as e:
        typer.echo(e)
        raise typer.Exit(code=1)
