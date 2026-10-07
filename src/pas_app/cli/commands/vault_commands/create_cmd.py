import typer

from pas_app.dependencies import get_keyring_tool
from pas_app.schemas.api import MessageResponse
from pas_app.services.file_utils import create_vault
from pas_app.core.api import Api
from pas_app.adapters.promts import (
    select_vault_name,
    select_master_password
)
from pas_app.schemas.vaults import CreateVaultData

# add logging!

async def create_vault_command(
    offline: bool
):
    """
    Dockstring
    """
    if offline:
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        assert keyring_data.current_user
        create_vault(username=keyring_data.current_user)
        typer.echo("New vault was successfully created")
        return
    
    vault_name = select_vault_name()
    master_password = select_master_password()
    data = CreateVaultData(
        vault_name=vault_name,
        vault_master_password=master_password
    )
    
    api = Api()
    response = await api.create_vault(vault_data=data)
    if response.status_code == 200:
        typer.echo("New vault was successfully created")
    else:
        assert isinstance(response.content, MessageResponse)
        typer.echo(response.content.detail)
    
    
    
    