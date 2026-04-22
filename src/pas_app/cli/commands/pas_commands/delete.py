import typer


from pas_app.services.file_utils import load_data, save_data
from pas_app.schemas.state import State
from pas_app.schemas.passwords import Password


def delete_command(
    ctx: typer.Context,
    
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
    state: State = ctx.obj
    
    data = load_data(state)
    
    if label.lower() == 'clear-all':
        if not typer.confirm('Удалить ВСЕ записи? Это действие необратимо!'):
            typer.echo('Очистка отменена.')
            return
        data.user_passwords = []
        save_data(state, data)
        typer.echo('Все данные были успешно удалены')
        return
    
    for pas in data.user_passwords:
        if label == pas.service:
            if not typer.confirm('Удалить запись? Это действие необратимо!'):
                typer.echo('Очистка отменена.')
                return
            data.user_passwords.remove(pas)
            typer.echo(f'Данные с меткой {label} были успешно удалены.')
            save_data(state, data)
            break
        else:
            typer.echo(f'Метка "{label}" не найдена.')
            return
