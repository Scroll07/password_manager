
import typer
import time

from pas_app.adapters.promts import cli_login_input
from pas_app.core.api import Api
from pas_app.core.logger import get_logger
from pas_app.schemas.api import Login_RegisterRequest, LoginResponse, MessageResponse
from pas_app.config import get_config

logger = get_logger()

async def login():
    config = get_config()
    config_data = config._refresh()
    api = Api()

    user_input_data = cli_login_input(username=config_data.local.default_user)
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
        config_data.local.default_user = user_api_data.username
        config_data.keyring.bearer_token = response.content.bearer_token.token
        config_data.keyring.refresh_token = response.content.refresh_token.token
        if config_data.local.default_user != user_api_data.username:
            config_data.keyring.master_password = ""
        config.save_config(config_data)

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

