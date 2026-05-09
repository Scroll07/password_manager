import asyncio
from datetime import datetime
import typer
import time

from pas_app.config import VAULTS
from pas_app.core.api import Api
from pas_app.config import config
from pas_app.exceptions import EchoException
from pas_app.schemas.api import MessageResponse


async def upload():
    config_data = config._refresh()
    api = Api(bearer_token=config_data.bearer_token)

    if api is None:
        raise EchoException("No api client, try to login firstly")
    if not config_data.default_user:
        raise EchoException("No default user in Config, try to login firstly")

    vault_file = VAULTS / f"{config_data.default_user}.json"

    if not vault_file.exists():
        raise EchoException(f"File {vault_file.name} does not exist")

    response = await api.upload(file_path=vault_file)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong response from server")
        raise typer.Exit(code=1)
    
    if response.status_code == 200:
        config_data.last_action = datetime.now()

        typer.echo(response.content.message)
        time.sleep(1)

        raise typer.Exit(code=0)
    else:
        typer.echo(
            f"Upload failed\nstatus_code: {response.status_code}, message: {response.content.message}"
        )
        raise typer.Exit(code=1)

def upload_command():
    """
    Загрузить backup vault на сервер.

    Сохраняет зашифрованный vault, чтобы можно было восстановить его на другом ПК.
    """
    asyncio.run(upload())