import asyncio
import typer


from pas_app.decorators import (
    check_current_values_dec,
    check_token_dec
)

user_app = typer.Typer(
    help="User commands for your account.",
    no_args_is_help=True
)

# Imports
from pas_app.cli.commands.user_commands.set_current_user_cmd import set_current_user
from pas_app.cli.commands.user_commands.change_password import change_user_password
from pas_app.cli.commands.user_commands.delete_user_cmd import delete_user_offline, delete_user_online
from pas_app.cli.commands.user_commands.deactivate_user import deactivate_user_online
from pas_app.cli.commands.user_commands.register_cmd import register_online # Добавить offline
from pas_app.cli.commands.user_commands.login_cmd import login

# Кароче смотри сюда, человек из будущего. Ты хочешь онлайн и оффлайн разновидность команд создания vault и user
# Проблема в том что декоратор для проверки токенов и сессии привязан к команде полностью, независимо от того какой флаг выбран
# Сейчас я вижу 2 пути:
#   - Проверять флаги внутри декоратора и уже из этого исходить проверять сессию или нет (муторно)
#   - Сделать 2 отдельные функции offline и online и на online повесить декоратор,
#     а внутри главной функции сделать выбирать по флагу if offline: ... elif online: ... 





# Проверка Bearer token + refresh token
# Здесь навесь на register_online
# Здесь навесь на delete_online
register_online = check_token_dec(register_online)
login = check_token_dec(login)
delete_user_online = check_token_dec(delete_user_online)
change_user_password = check_token_dec(change_user_password)

# Проверка на Current User is not None
set_current_user = check_current_values_dec(set_current_user)
change_user_password = check_current_values_dec(change_user_password)
delete_user_offline = check_current_values_dec(delete_user_offline)









def register_command():
    """
    Register a new API account.

    Creates a new account for working with remote vault backup storage.
    You will be prompted to enter a username and password for registration.

    Examples:
        pas api register

    After successful registration, a local vault will be created.
    """
    asyncio.run(register_online())

def login_command():
    """
    Log into an existing API account.

    Authenticates with the API and obtains access tokens for subsequent
    requests. Tokens are securely stored in the local configuration.

    Examples:
        pas api login

    You will be prompted to enter your username and password.
    """
    asyncio.run(login())



def change_user_password_command():
    """
    Change API account password.

    Updates the password for your API account while keeping backups
    and other account data intact.

    Examples:
        pas api change-password

    You will be prompted to enter a new password in a secure input window.
    """
    asyncio.run(change_user_password())


def delete_user_command(
    offline: bool = typer.Option(False, '--offline', help="Delete user account locally only")
):
    """
    Delete your API account.

    Removes your account from the server or locally.
    Use --offline to delete only the local reference without touching
    the server account.

    Examples:
        pas api delete              # Delete server account

        pas api delete --offline    # Remove local user data only
    """
    if offline:
        delete_user_offline()
    else:
        asyncio.run(delete_user_online())


def deactivate_user_command():
    """
    Deactivate your API account.

    Temporarily disables your account on the server while keeping
    all your data intact. You can reactivate it later.

    Examples:
        pas api deactivate
    """
    asyncio.run(deactivate_user_online())




user_app.command('register')(register_command)
user_app.command('login')(login_command)
user_app.command("set")(set_current_user)
user_app.command("change-password")(change_user_password)
user_app.command("delete")(delete_user_command)




