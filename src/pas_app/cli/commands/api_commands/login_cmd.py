import typer
import time


from pas_app.adapters.promts import cli_register_input
from pas_app.schemas.state import State
from pas_app.services.password import create_user_vault
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest

async def login_command(
    ctx: typer.Context
):
    state: State = ctx.obj
    if state.api is None:
        api = Api()
        state.api = api
    else:
        api = state.api
    
    user_input_data = cli_register_input() #cli_login_input()
    user_api_data = Login_RegisterRequest(
        username=user_input_data.username,
        password=user_input_data.password
    )
    
    is_login = await api.login(user_api_data)
    if is_login:
        state.current_user = user_api_data.username
            
        typer.echo(f"Successful login, Hi {user_api_data.username}!")

        raise typer.Exit(code=1)
    else:
        typer.echo("Register failed")
        raise typer.Exit(code=0)
        
