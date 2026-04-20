import csv
import json
import typer

from pas_app.config import BASE_DIR
from services.password import delete_file, load_data, save_data



def import_data(
    filename: str = typer.Argument(..., help="Имя файла для импорта (например, export.json)"),
    format: str = typer.Option("json", "--format", help="Формат: json или csv (по умолчанию: json)"),
    overwrite: bool = typer.Option(False, "--overwrite", help="Перезаписать существующие метки"),
    will_delete: bool = typer.Option(False, '--delete', help="Удалять ли файл json сразу после импорта")
):
    '''
     Импорт данных в store.bin из файла.

    Примеры:

      pas import my_export.json --format json --overwrite

      pas import my_export.csv --format csv

      pas import my_export.json --delete             # Импорт из JSON с удалением файла после

      pas import my_export.csv --format csv --delete # Импорт из CSV с удалением файла после
    '''
    filename_path = BASE_DIR / filename
    if not filename_path.exists():
        typer.echo(f'Файл {filename} не найден.')
        return
    if format.lower() == 'json':
        with open(filename_path, 'r', encoding='utf-8') as f:
            import_data = json.load(f) 
    elif format.lower() == "csv":
        import_data = {}
        with open(filename_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            headers = next(reader)  # Пропустить заголовок
            for row in reader:
                if len(row) >= 4:
                    label, username, password, note = row[:4]
                    import_data[label] = {"username": username, "password": password, "note": note}
    else:
        typer.echo("Неподдерживаемый формат. Используйте json или csv.")
        return

    current_data = load_data()

    if not typer.confirm("Импорт может изменить существующие записи. Продолжить?"):
        typer.echo('Импорт отменен. ВЫХОД')
        return
    
    for label, entry in import_data.items():
        if label in current_data and not overwrite:
            typer.echo(f"Метка {label} уже существует. Пропускаем (Используйте --overwrite для замены).")
            continue
        current_data[label] = entry

    save_data(current_data)
    typer.echo(f'Данные успешно импортированы из {filename}')
    if will_delete:
        delete_file(filename_path)
    else:
        typer.echo(f'Файл {filename} не был удален.')