import typer

from pas_app.config import STORE
from pas_app.services.password import load_data, save_data


def delete_command(
    label: str = typer.Argument(..., help='Метка для удаления или "clear-all" для полной очистки')
):
    '''
     Удалить запись по метке или все записи.
    
    Требует подтверждения перед удалением для безопасности.

    Для полной очистки всех данных используйте "clear-all".
    
    Примеры:

      pas.py delete github-1      # Удалить конкретную запись

      pas.py delete "clear-all"   # Удалить все записи (в кавычках!)
    '''
    if not STORE.exists():
        typer.echo('Записей нет, файл не существует.')
        return
    
    data = load_data()
    
    if label.lower() == 'clear-all':
        if not typer.confirm('Удалить ВСЕ записи? Это действие необратимо!'):
            typer.echo('Очистка отменена.')
            return
        data.clear()
        save_data(data)
        typer.echo('Все данные были успешно удалены')
        return
    
    if label in data:
        if not typer.confirm('Удалить запись? Это действие необратимо!'):
            typer.echo('Очистка отменена.')
            return
        del data[label]
        typer.echo(f'Данные с меткой {label} были успешно удалены.')
        save_data(data)
    else:
        typer.echo(f'Метка "{label}" не найдена.')
        return
