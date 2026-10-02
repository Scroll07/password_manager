import typer
import shutil

from pas_app.adapters.promts import choose_delete_user
from pas_app.core.settings import VAULTS
from pas_app.services.file_utils import get_vault_usernames


def delete_user(
    offline: bool = typer.Option(False, '--offline', help="Oflline deleting user"),
    online: bool = typer.Option(False, '--online', help="Online deleting user")
):
    """
    Delete a local vault user.

    The command deletes only the local vault file for the selected user.
    It does not remove the user from the server.

    Examples:
        pas user delete

    After running the command, choose a user from the list and confirm
    the deletion prompt.
    """
    
    
    if not offline and not online:
        typer.echo() # можно только одно значение
    elif offline and online:
        typer.echo() # можно только одно значение
    elif offline:
        usernames = get_vault_usernames()
        selected = choose_delete_user(usernames=usernames)
        user_dir = VAULTS / selected
        shutil.rmtree(user_dir)
    elif online:
       # В начале добавить проверку доступа к vault, если пользователь не знает пароль от него то удалить онлайн нельзя
        ... # метод из core/api.py для отправки запроса на удалении пользователя
    
    