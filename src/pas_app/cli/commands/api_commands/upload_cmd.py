from datetime import datetime

import typer
import time


from pas_app.config import VAULTS
from pas_app.schemas.state import State
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest

async def login_command(
    ctx: typer.Context
):
    state: State = ctx.obj
    
    api = state.api
    config = state.config
    cfg_data = config.load_config()
    
    if api is None:
        raise ValueError("No api client, try to login firstly")
    if not cfg_data.default_user:
        raise ValueError("No default user in Config, try to login firstly")
    
    vault_file = VAULTS / f'{cfg_data.default_user}.json'
    
    if not vault_file.exists():
        raise FileExistsError(f"File {vault_file.name} does not exist")    
    
    response = await api.upload(file_path=vault_file)
    if response.status_code == 200:            
        state.last_action = datetime.now()
        
        typer.echo(response.content.message)
        time.sleep(1)
        

        raise typer.Exit(code=0)
    else:
        typer.echo(f'Upload failed\nstatus_code: {response.status_code}, message: {response.content.message}')
        raise typer.Exit(code=1)
        
