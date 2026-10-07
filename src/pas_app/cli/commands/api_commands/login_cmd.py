
import typer
import time

from pas_app.adapters.promts import cli_login_input
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest, LoginResponse, MessageResponse
from pas_app.dependencies import (
    get_logger,
    get_keyring_tool
)



logger = get_logger()

async def login(
):
    keyring = get_keyring_tool()
    keyring_data = keyring.load()

    api = Api()

    user_input_data = cli_login_input(username=keyring_data.current_user)
    username = user_input_data.username
    password = user_input_data.password

    user_api_data = Login_RegisterRequest(username=username, password=password)
    logger.info(f"Login attempt for user: {username}")

    response = await api.login(user_api_data)
    logger.info(f"Login response status: {response.status_code}")
    if not isinstance(response.content, LoginResponse):
        if isinstance(response.content, MessageResponse):
            logger.error(f"Login failed for user {username}: {response.content.detail}")
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        logger.error(f"Wrong content from API for user {username}: {type(response.content)}")
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
        
    if response.status_code == 200:
        if keyring_data.current_user != username:
            keyring_data.master_password = ''
        keyring_data.current_user = username
        keyring_data.bearer_token = response.content.bearer_token.token
        keyring_data.refresh_token = response.content.refresh_token.token
        
        keyring.save(data=keyring_data)

        typer.echo(response.content.detail)
        time.sleep(1)

        logger.info(f"Login successful for user: {username}")
        raise typer.Exit(code=0)
    else:
        logger.error(f"Login failed for user {username}: status_code {response.status_code}, message: {response.content.detail}")
        typer.echo(
            f"Login failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)

