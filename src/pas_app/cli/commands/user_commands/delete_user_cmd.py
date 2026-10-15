import typer
import shutil

from pas_app.adapters.promts import choose_delete_user
from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import MessageResponse, UserDataResponse
from pas_app.services.file_utils import get_vault_usernames
from pas_app.dependencies import get_keyring_tool

def delete_user_offline():
    usernames = get_vault_usernames()
    selected = choose_delete_user(usernames=usernames)
    user_dir = VAULTS / selected
    shutil.rmtree(user_dir)
        
async def delete_user_online():        
    api = Api()
    response = await api.user_me()
    if response.status_code != 200:
        assert isinstance(response.content, MessageResponse)
        typer.echo(response.content.detail)
        raise typer.Exit(code=1)
    
    assert isinstance(response.content, UserDataResponse)
    user_data = response.content.data
    username = user_data.username
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    choice = typer.confirm(f"Delete user with username: {username} this action will permanently delete the user and data.\ny/n")
    if not choice:
        typer.echo("Canceling...")
        raise typer.Exit(code=0)
        
    response = await api.delete_user()
    assert isinstance(response.content, MessageResponse)
    if response.status_code != 200:
        typer.echo(response.content.detail)
        raise typer.Exit(code=1)
       
    typer.echo(response.content.detail)
       
    if keyring_data.current_user == username:
        keyring_data.current_user = ""
        typer.echo("Reseting current user...")
       
       
    # Удаление vaults локально
    user_dir = VAULTS / username
    shutil.rmtree(user_dir)
    typer.echo(f"Vaults of {username} were deleted")
       
    
       # В начале добавить проверку доступа к vault, если пользователь не знает пароль от него то удалить онлайн нельзя
       # метод из core/api.py для отправки запроса на удалении пользователя
    
    