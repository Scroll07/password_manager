import asyncio

import typer
import time

from pas_app.adapters.promts import cli_login_input
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest, LoginResponse, MessageResponse
from pas_app.schemas.passwords import KeyringValues 
from pas_app.config import config
from pas_app.core.crypto import set_keyring_value

async def login():
    config_data = config._refresh()
    api = Api(bearer_token=config_data.keyring.bearer_token)

    user_input_data = cli_login_input(username=config_data.local.default_user)
    username = user_input_data.username
    password = user_input_data.password

    user_api_data = Login_RegisterRequest(username=username, password=password)

    response = await api.login(user_api_data)
    if not isinstance(response.content, LoginResponse):
        if isinstance(response.content, MessageResponse):
            typer.echo(response.content.message)
            raise typer.Exit(code=1)
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
        
    if response.status_code == 200:
        config_data.local.default_user = user_api_data.username
        config_data.keyring.bearer_token = response.content.access_token
        config_data.keyring.refresh_token = response.content.refresh_token
        if config_data.local.default_user != user_api_data.username:
            config_data.keyring.master_password = ""
        config.save_config(config_data)

        typer.echo(response.content.message)
        time.sleep(1)

        raise typer.Exit(code=0)
    else:
        typer.echo(
            f"Login failed\nstatus_code: {response.status_code}, message: {response.content.message}"
        )
        raise typer.Exit(code=1)

def login_command():
    """
    Войти в API-аккаунт.

    Получает access token для последующих запросов.
    """
    asyncio.run(login())