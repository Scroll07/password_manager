
import typer


from pas_app.adapters.promts import cli_register_input
from pas_app.services.password import create_user_vault
from pas_app.core.api import Api
from pas_app.core.logger import get_logger
from pas_app.schemas.api import Login_RegisterRequest, MessageResponse
from pas_app.config import get_config

logger = get_logger()

async def register():
    config = get_config()
    config_data = config._refresh()
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

        create_user_vault(username=username)

        config_data.local.default_user = username
        config.save_config(data=config_data)


        #Restart login so the user is logged in immediately

        # login logic

        # typer.echo(f"Successful login, Hi {user_api_data.username}!")
        # time.sleep(1)
        logger.info(f"Register successful for user: {username}")
        raise typer.Exit(code=0)

    else:
        logger.error(f"Register failed for user {username}: status_code {response.status_code}, message: {response.content.detail}")
        typer.echo(
            f"Register failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)

