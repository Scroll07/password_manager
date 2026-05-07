import asyncio

import typer
import time


from pas_app.adapters.promts import cli_login_input
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest
from pas_app.config import config

async def login():
    config_data = config._refresh()
    api = Api(bearer_token=config_data.bearer_token)

    user_input_data = cli_login_input()
    username = user_input_data.username
    password = user_input_data.password

    user_api_data = Login_RegisterRequest(username=username, password=password)

    response = await api.login(user_api_data)
    if response.status_code == 200:
        config_data.default_user = user_api_data.username
        config_data.bearer_token = response.content.access_token # type: ignore
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
    asyncio.run(login())