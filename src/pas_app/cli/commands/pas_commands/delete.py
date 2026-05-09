import typer


from pas_app.services.file_utils import load_data, save_data
from pas_app.config import config


def delete_command(
    label: str = typer.Argument(
        ..., help='Метка для удаления или "clear-all" для полной очистки'
    ),
):
    """
     Удалить запись по метке или все записи.

    Требует подтверждения перед удалением для безопасности.

    Для полной очистки всех данных используйте "clear-all".

    Примеры:

      pas.py delete github-1      # Удалить конкретную запись

      pas.py delete "clear-all"   # Удалить все записи (в кавычках!)
    """

    data = load_data(config=config)

    if label.lower() == "clear-all":
        if not typer.confirm("Удалить ВСЕ записи? Это действие необратимо!"):
            typer.echo("Очистка отменена.")
            return
        data.user_passwords = []
        save_data(vault_data=data)
        typer.echo("Все данные были успешно удалены")
        raise typer.Exit(code=0)

    for pas in data.user_passwords:
        if label == pas.service:
            if not typer.confirm("Удалить запись? Это действие необратимо!"):
                typer.echo("Очистка отменена.")
                typer.Exit(code=0)
            data.user_passwords.remove(pas)
            typer.echo(f"Данные с меткой {label} были успешно удалены.")
            save_data(vault_data=data)
            break
        else:
            typer.echo(f'Метка "{label}" не найдена.')
            raise typer.Exit(code=0)
