import typer

from pas_app.config import BASE_DIR
from pas_app.schemas.state import State
from pas_app.schemas.passwords import UserVault
from pas_app.services.file_utils import delete_file, load_data, save_data


def import_data(
    ctx: typer.Context,
    
    filename: str = typer.Argument(
        ..., help="Имя файла для импорта (например, export.json)"
    ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Перезаписать существующие метки"
    ),
    will_delete: bool = typer.Option(
        False, "--delete", help="Удалять ли файл json сразу после импорта"
    ),
):
    """
     Импорт данных в store.bin из файла.

    Примеры:

      pas import my_export.json --format json --overwrite

      pas import my_export.json --delete             # Импорт из JSON с удалением файла после
    """
    state: State = ctx.obj
    
    filename_path = BASE_DIR / filename
    if not filename_path.exists():
        typer.echo(f"Файл {filename} не найден.")
        raise typer.Exit(code=1)
    
    with open(filename_path, "r", encoding="utf-8") as f:
        import_data = f.read()

    import_data = UserVault.model_validate(import_data)
    current_data = load_data(state=state)

    if import_data.username != current_data.username or import_data.salt != current_data.salt:
        raise ValueError("Wrong username or salt")

    if not typer.confirm("Импорт может изменить существующие записи. Продолжить?"):
        typer.echo("Импорт отменен. ВЫХОД")
        return

    for label, entry in import_data.items():
        if label in current_data and not overwrite:
            typer.echo(
                f"Метка {label} уже существует. Пропускаем (Используйте --overwrite для замены)."
            )
            continue
        current_data[label] = entry

    save_data(current_data)
    typer.echo(f"Данные успешно импортированы из {filename}")
    if will_delete:
        delete_file(filename_path)
    else:
        typer.echo(f"Файл {filename} не был удален.")
