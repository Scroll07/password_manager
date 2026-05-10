import typer

from pas_app.services.file_utils import load_data, dump_last_matches
from pas_app.services.password import print_passwords
from pas_app.config import config


def get_command(
    service: str = typer.Argument(
        ..., help='Метка сервиса (например: github) или "all"/"." для всех записей'
    ),
    show: bool = typer.Option(
        False, "--show", help="Показать пароли открытым текстом (по умолчанию скрыты)"
    ),
):
    """
    Показать информацию о записях по метке или все записи.

    Поддерживает поиск по началу метки - "github" найдет github, github-1, github-2 и т.д.

    По умолчанию пароли скрыты символами ******, используйте --show для отображения.

    Для всех записей используйте "all" или ".".

    Примеры:

      pas.py get github           # Все записи, начинающиеся с "github", пароли скрыты

      pas.py get github --show    # То же, но с открытыми паролями

      pas.py get all              # Все записи, пароли скрыты
    """
    data = load_data(config=config)
    passwords = data.user_passwords

    if not data or not data.user_passwords:
        typer.echo("Записей нет")
        return

    if service.lower() == "." or service.lower() == "all":
        passwords = sorted(passwords, key=lambda p: p.service)
    else:
        passwords = sorted(
            [p for p in passwords if p.service.lower().startswith(service.lower())],
            key=lambda p: p.service,
        )

    print_passwords(passwords=passwords, show=show)

    matches = [p.service for p in passwords]
    dump_last_matches(matches=matches)
