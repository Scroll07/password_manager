
import asyncio

import typer


from pas_app.adapters.promts import cli_register_input
from pas_app.cli.commands.user_commands.login_cmd import login
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest, MessageResponse
from pas_app.dependencies import (
    get_logger,
    get_keyring_tool
)
logger = get_logger()

async def register_online():
    api = Api()

    user_input_data = cli_register_input()
    username = user_input_data.username
    user_api_data = Login_RegisterRequest(
        username=username, password=user_input_data.password
    )

    logger.info(f"Register attempt for user: {username}")
    response = await api.register(user_api_data)
    logger.info(f"Register response status: {response.status_code}")

    if not isinstance(response.content, MessageResponse):
        logger.error(f"Wrong response from server for user {username}: {type(response.content)}")
        typer.echo("Wrong response from server")
        raise typer.Exit(code=1)

    if response.status_code == 201:
        typer.echo(response.content.detail)

        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        keyring_data.current_user = username
        keyring.save(data=keyring_data)
        
        logger.info(f"Register successful for user: {username}")
        await asyncio.sleep(1)
        
        await login()
        
        raise typer.Exit(code=0)
    else:
        logger.error(f"Register failed for user {username}: status_code {response.status_code}, message: {response.content.detail}")
        typer.echo(
            f"Register failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)

