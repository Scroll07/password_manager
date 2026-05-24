
import typer


from pas_app.adapters.promts import cli_register_input
from pas_app.services.password import create_user_vault
from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest, MessageResponse
from pas_app.config import config

async def register():
    config_data = config._refresh()
    api = Api()

    user_input_data = cli_register_input()
    user_api_data = Login_RegisterRequest(
        username=user_input_data.username, password=user_input_data.password
    )

    response = await api.register(user_api_data)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong response from server")
        raise typer.Exit(code=1)
    
    if response.status_code == 201:
        typer.echo(response.content.message)

        create_user_vault(username=user_input_data.username)
        
        config_data.local.default_user = user_input_data.username
        config.save_config(data=config_data)


        #   #Запустить логин чтобы он сразу залогинился

        # login logic

        # typer.echo(f"Successful login, Hi {user_api_data.username}!")
        # time.sleep(1)
        raise typer.Exit(code=0)

    else:
        typer.echo(
            f"Register failed\nstatus_code: {response.status_code}, message: {response.content.message}"
        )
        raise typer.Exit(code=1)

