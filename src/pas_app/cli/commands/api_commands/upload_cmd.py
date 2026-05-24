import typer
import time

from pas_app.config import VAULTS
from pas_app.core.api import Api
from pas_app.config import config
from pas_app.schemas.api import MessageResponse
from pas_app.adapters.promts import choose_name_for_backup
from pas_app.services.file_utils import load_data


async def upload():
    config_data = config._refresh()
    api = Api()

    if api is None:
        typer.echo("No api client, try to login firstly")
        raise typer.Exit()
    if not config_data.local.default_user:
        typer.echo("No default user in Config, try to login firstly")
        raise typer.Exit()

    vault_file = VAULTS / f"{config_data.local.default_user}.json"

    if not vault_file.exists():
        typer.echo(f"File {vault_file.name} does not exist")

    #name - ask name for backup to show for user
    #count - get summury of rows in user vault - len(user_passwords)
    name = choose_name_for_backup()

    user_data = load_data(config=config)
    count = len(user_data.user_passwords)
    
    response = await api.upload(file_path=vault_file, name=name, rows=count)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong response from server")
        raise typer.Exit(code=1)
    
    if response.status_code == 200:

        typer.echo(response.content.detail)
        time.sleep(1)

        raise typer.Exit(code=0)
    else:
        typer.echo(
            f"Upload failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)

