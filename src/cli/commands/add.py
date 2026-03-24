import typer
import secrets

from src.core.services import load_data, save_data


def add_command(
    service: str = typer.Argument(..., help="Название сервиса (например: github, vk, yandex)"),
    username: str = typer.Option(..., '-u', '--username', help="Имя пользователя или email"),
    password: str | None = typer.Option(None, '-p', '--password', help="Пароль (если не указан, используйте --gen)"),
    note: str | None = typer.Option(None, '--note', help="Дополнительная заметка или описание"),
    gen: bool = typer.Option(False, '--gen', help="Сгенерировать случайный пароль"),
    length: int = typer.Option(16, '--length', help="Длина генерируемого пароля (по умолчанию: 16)")
):
    '''
    Сохранение Логина/Пароля.

    Примеры:

      pas.py add github -u myuser -p mypass123

      pas.py add vk -u user@email.com --gen --length 20

      pas.py add work-email -u john@company.com --gen --note "Рабочая почта"
    '''
    if password is not None:
        if gen:
            typer.echo('Нельзя вводить одновременно -p И --gen \n ВЫХОД')
            return
    elif password is None and gen:
        password = secrets.token_urlsafe(length)
    elif password is None and gen == False:
        typer.echo('Нужно указать либо -p либо --gen')
        return
        

    data = load_data()

    labels = set(data)
    base = service.lower()
    candidate = base
    i=1
    while candidate in labels:
        candidate = base + '-' + str(i)
        i+=1
    entry = {"username": username, "password": password, "note": note}
    data[candidate] = entry
    save_data(data)