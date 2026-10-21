import typer

from pas_app.dependencies import get_keyring_tool
from pas_app.schemas.api import CreateVaultDataRequest, CreateVaultResponse, MessageResponse
from pas_app.services.file_utils import create_vault, load_encrypted_vault, create_vault_path
from pas_app.core.api import Api
from pas_app.adapters.promts import (
    select_vault_name,
    select_master_password
)

# add logging!



def create_vault_offline():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    vault_name = select_vault_name()
    master_password = select_master_password()
    create_vault(username=keyring_data.current_user, vault_name=vault_name, master_password=master_password)
    typer.echo("\nNew vault was successfully created\n")
    raise typer.Exit(code=0)

async def create_vault_online():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    vault_name = select_vault_name()
    master_password = select_master_password()
    username = keyring_data.current_user
    
    try:
        create_vault(username=username, vault_name=vault_name, master_password=master_password)
    except FileExistsError:
        typer.echo("\nVault with this name already exists\nPlease, choose another one\n")
        raise typer.Exit(code=1)
    
    encrypted = load_encrypted_vault(username=username, vault_name=vault_name)
    payload = CreateVaultDataRequest(
        name=encrypted.name,
        salt=encrypted.salt,
        encrypted_dek=encrypted.encrypted_dek
    )
    
    api = Api()
    response = await api.create_vault(payload=payload)
    if response.status_code == 201:
        assert isinstance(response.content, CreateVaultResponse)
        created_vault_path = create_vault_path(username=username, vault_name=vault_name)
        if not created_vault_path.exists():
            typer.echo("\nUnexpected error, vault not created\n")
            raise typer.Exit(code=1)
        
        encrypted.id = response.content.vault_id
        
        with open(created_vault_path, 'w', encoding='utf-8') as f:
            f.write(encrypted.model_dump_json(indent=4))

        typer.echo("\nNew vault was successfully created\n")
        raise typer.Exit(code=0)
    else:
        assert isinstance(response.content, MessageResponse)
        typer.echo(response.content.detail)
    
    
    
    
    