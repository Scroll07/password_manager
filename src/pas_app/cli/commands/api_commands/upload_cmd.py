import typer
import time

from pas_app.config import VAULTS
from pas_app.core.api import Api
from pas_app.core.logger import get_logger
from pas_app.config import get_config
from pas_app.schemas.api import MessageResponse
from pas_app.adapters.promts import choose_name_for_backup
from pas_app.services.file_utils import load_data

logger = get_logger()

async def upload():
    config = get_config()
    config_data = config._refresh()
    api = Api()

    if api is None:
        typer.echo("No API client. Try to login first")
        raise typer.Exit()
    if not config_data.local.default_user:
        typer.echo("No default user in config. Try to login first")
        raise typer.Exit()

    vault_file = VAULTS / f"{config_data.local.default_user}.json"

    if not vault_file.exists():
        typer.echo(f"File {vault_file.name} does not exist")

    #name - ask name for backup to show for user
    #rows - get summary of rows in user vault - len(user_passwords)
    name = choose_name_for_backup()

    user_data = load_data(config=config)

    count = len(user_data.user_passwords)

    logger.info(f"Upload attempt for user: {config_data.local.default_user}, backup name: {name}")
    response = await api.upload(file_path=vault_file, name=name, rows=count)
    logger.info(f"Upload response status: {response.status_code}")

    if not isinstance(response.content, MessageResponse):
        logger.error(f"Wrong response from server for user {config_data.local.default_user}: {type(response.content)}")
        typer.echo("Wrong response from server")
        raise typer.Exit(code=1)

    if response.status_code == 200:

        typer.echo(response.content.detail)
        time.sleep(1)

        logger.info(f"Upload successful for user: {config_data.local.default_user}, backup name: {name}")
        raise typer.Exit(code=0)
    else:
        logger.error(f"Upload failed for user {config_data.local.default_user}: status_code {response.status_code}, message: {response.content.detail}")
        typer.echo(
            f"Upload failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)

