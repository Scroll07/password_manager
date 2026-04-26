import typer
import time


from pas_app.adapters.promts import cli_register_input
from pas_app.schemas.state import State
from pas_app.services.password import create_user_vault
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest

async def register_command(
    ctx: typer.Context
):
    state: State = ctx.obj
    config = state.config
    
    if state.api is None:
        api = Api()
        state.api = api
    else:
        api = state.api
    
    user_input_data = cli_register_input()
    user_api_data = Login_RegisterRequest(
        username=user_input_data.username,
        password=user_input_data.password
    )
    
    is_registered = await api.register(user_api_data)
    if is_registered:
        typer.echo(f"Registered new accaunt - {user_api_data.username}")

        config.create_empty_config(user_input_data.username)

            
        typer.echo(f"Successful login, Hi {user_api_data.username}!")
        time.sleep(1)
    
    #     #Запустить логин чтобы он сразу залогинился

    
        raise typer.Exit(code=1)
    else:
        typer.echo("Register failed")
        raise typer.Exit(code=0)
        
