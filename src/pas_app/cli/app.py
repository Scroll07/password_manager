import typer

from pas_app.core.services import check_session

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


app = typer.Typer(help="""
Менеджер паролей: безопасное хранение логинов и паролей.

Основной рабочий процесс:

  1. Добавьте запись:
     pas add <сервис> -u <логин> --gen

  2. Просмотрите список:
     pas list

  3. Найдите нужную запись:
     pas get <метка_или_начало>

  4. Скопируйте пароль:
     pas copy <номер_из_таблицы>

Дополнительные команды:

  - Изменить запись:
    pas edit <метка> [опции]

  - Поиск по полям:
    pas find <запрос>

  - Удалить запись:
    pas del <метка>          (или 'clear-all' для полной очистки)

  - Сбросить сессию:
    pas reset-session

 - Экспорт данных:
    pas export <файл> [--format json|csv] [--include-passwords]

  - Импорт данных:
    pas import <файл> [--format json|csv] [--overwrite]

Все данные надёжно шифруются в файле store.bin.
Для справки по любой команде используйте:
  pas <команда> --help
""",
no_args_is_help=True)

app.command("add")(add_command)
app.command("list")(list_command)
app.command("get")(get_command)
app.command("copy")(copy)
app.command("del")(delete_command)
app.command("find")(find_command)
app.command("edit")(edit_command)
app.command("export")(export_command)
app.command("import")(import_data)
app.command("reset-session")(reset_session)
app.command("change-master")(change_master)
app.command("get-path")(get_path)

#KEYS
app.command("create-key")(create_password_command)




@app.callback()
def main():
    """Инициализация сессии при запуске."""
    check_session()