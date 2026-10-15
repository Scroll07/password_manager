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



def create_vault_offline():
    vault_name = select_vault_name()
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    create_vault(username=keyring_data.current_user, vault_name=vault_name)
    typer.echo("New vault was successfully created")
    raise typer.Exit(code=0)

async def create_vault_online():
    """
    Dockstring
    """
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
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    create_vault(username=keyring_data.current_user, vault_name=vault_name)
    typer.echo("New vault was successfully created")
    raise typer.Exit(code=0)
    
    
    
    