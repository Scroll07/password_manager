import csv
import json
import typer

from pas_app.config import EXPORT_DIR
from pas_app.services.file_utils import load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password


def export_command(
    ctx: typer.Context,
    
    filename: str = typer.Argument(..., help="Имя файла для экспорта (например, export.json)"),
    no_passwords: bool = typer.Option(False, "--no-passwords", help="Включить пароли в экспорт (опасно!)")
    # format: str = typer.Option("json", "--format", help="Формат: json или csv (по умолчанию: json)"),
):
    '''
    Экспорт данных из store.bin в файл.

    Примеры:

      pas export my_export.json --format json --no-passwords

      pas export my_export.csv --format csv
    '''

    state: State = ctx.obj
    data = load_data(state=state)

    if not typer.confirm("Экспорт может раскрыть чувствительные данные. Продолжить?"):
        typer.echo("Экспорт отменен. ВЫХОД")
        return

    export_data = {}
    for pas in data.user_passwords:
        export_pas = {
            "username": pas.username,
            "note": pas.note
        }
        if not no_passwords:
            export_pas["passwords"] = pas.password
        export_data[pas.service] = export_pas
        
    
    filename_path = EXPORT_DIR / filename
    with open(filename_path, 'w', encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    typer.echo(f"данные экспортированы в {filename_path} (JSON)")
    typer.Exit(code=0)