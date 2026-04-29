import typer
import time


from pas_app.adapters.promts import cli_login_input
from pas_app.schemas.state import State
from pas_app.services.password import create_user_vault
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest

async def login_command(
    ctx: typer.Context
):
    state: State = ctx.obj
    config = state.config
    if state.api is None:
        api = Api()
        state.api = api
    else:
        api = state.api
    
    user_input_data = cli_login_input()
    username =  user_input_data.username
    password = user_input_data.password
    
    user_api_data = Login_RegisterRequest(
        username=username,
        password=password
    )
    
    response = await api.login(user_api_data)
    if response.status_code == 200:
        state.current_user = user_api_data.username
        
        cfg_data = config.load_config()
        cfg_data.default_user = user_api_data.username
        config.save_config(cfg_data)
            
        typer.echo(response.content.message)
        time.sleep(1)
        

        raise typer.Exit(code=0)
    else:
        typer.echo(f'Login failed\nstatus_code: {response.status_code}, message: {response.content.message}')
        raise typer.Exit(code=1)
        
