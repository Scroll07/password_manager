import csv
import json
import typer

from pas_app.config import BASE_DIR, STORE
from pas_app.services.password import load_data


def export_command(
    filename: str = typer.Argument(..., help="Имя файла для экспорта (например, export.json)"),
    format: str = typer.Option("json", "--format", help="Формат: json или csv (по умолчанию: json)"),
    include_passwords: bool = typer.Option(False, "--include-passwords", help="Включить пароли в экспорт (опасно!)")
):
    '''
    Экспорт данных из store.bin в файл.

    Примеры:

      pas export my_export.json --format json --include-passwords

      pas export my_export.csv --format csv
    '''
    filename_path = BASE_DIR / filename
    if not STORE.exists():
        typer.echo('Нет данных для экспорта.')
        return

    data = load_data()
    if not typer.confirm("Экспорт может раскрыть чувствительные данные. Продолжить?"):
        typer.echo("Экспорт отменен. ВЫХОД")
        return

    export_data = {}
    for label, entry in data.items():
        export_entry = {
            "username": entry.get("username", ""),
            "note": entry.get("note", "")
        }
        if include_passwords:
            export_entry["password"] = entry.get("password", "")
        export_data[label] = export_entry

    if format.lower() == "json":
        with open(filename_path, 'w', encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        typer.echo(f"данные экспортированы в {filename_path} (JSON)")
    elif format.lower() == 'csv':
        with open(filename_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["Метка", "Логин", "Пароль", "Заметка"])
            for label, entry in export_data.items():
                writer.writerow([label, entry.get("username", ""), entry.get("password", ""), entry.get("note", "")])
        typer.echo(f"Данные экспортированы в {filename_path} (CSV).")
    else:
        typer.echo("Неправильный формат, используйте JSON или CSV.")