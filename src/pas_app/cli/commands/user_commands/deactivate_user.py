import typer

from pas_app.core.api import Api
from pas_app.schemas.api import MessageResponse, UserDataResponse
from pas_app.dependencies import get_keyring_tool


async def deactivate_user_online():        
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
    choice = typer.confirm(f"Deactivate user with username: {username}\ny/n")
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
       
    