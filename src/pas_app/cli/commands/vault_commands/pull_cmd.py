

import typer

from pas_app.adapters.promts import print_and_choose_vault
from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import MessageResponse, PullRequestData, PullResponse, PullStatuses, VaultsDataResponse
from pas_app.services.file_utils import (
    load_encrypted_vault,
    create_vault_path
)
from pas_app.dependencies import get_keyring_tool

async def pull_vault(
    force: bool,
    create_new_file: bool
):
    api = Api()
    response = await api.get_vaults()
    if not isinstance(response.content, VaultsDataResponse):
        if isinstance(response.content, MessageResponse):
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        else:
            typer.echo("Wrong content from api")
            raise typer.Exit(code=1)
    
    vaults = response.content.vaults
    if not vaults:
        typer.echo("You have no vaults")
        raise typer.Exit(code=0)

    vault = print_and_choose_vault(vaults=vaults, text="Choose vault to pull")
    
    # find vault with such name to get version
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    file = create_vault_path(username=keyring_data.current_user, vault_name=vault.name)
    version = None
    if file.exists():
        encrypted_data = load_encrypted_vault(username=keyring_data.current_user, vault_name=vault.name)
        version = encrypted_data.version
    
    request_data = PullRequestData(
        vault_id=vault.id,
        version=version,
        force=force
    )
    response = await api.pull_vault(payload=request_data)

    if not type(response.content) == PullResponse:
        typer.echo("Wrong server response type")
        raise typer.Exit(code=1)
    
    if isinstance(response.content, MessageResponse):
        typer.echo(response.content.detail)
        raise typer.Exit(code=1)


    status = response.content.status

    if status == PullStatuses.NOT_FOUND:
        typer.echo("Vault not found on server")
        raise typer.Exit(code=1)

    elif status == PullStatuses.LOCAL_AHEAD:
        typer.echo("Local version is newer than server version.\nPush first or use '--force' to overwrite local file")
        raise typer.Exit(code=1)

    elif status == PullStatuses.UP_TO_DATE:
        typer.echo("Vault is already up to date with server.")
        return

    elif status == PullStatuses.PULLED:
        vault_data = response.content.vault_data
        if not vault_data:
            typer.echo("Server returned PULLED status, but vault data is missing")
            raise typer.Exit(code=1)

        # Сохраняем обновленные данные в локальный файл
        if create_new_file:
            user_dir = VAULTS / keyring_data.current_user
            user_dir.mkdir(exist_ok=True)
            file = user_dir / f'{vault_data.name}_v1.{vault_data.version}.json'
        else:
            if file.exists():
                typer.confirm(
                    f"Local vault file '{file.name}' already exists and will be overwritten. Do you want to continue?",
                    abort=True
                )
        
        with open(file, "w", encoding="utf-8") as f:
            f.write(vault_data.model_dump_json(indent=4))

        if force:
            typer.echo("Forced pull...")
        if not create_new_file:
            typer.echo("Successful pull. Local changes were overwritten")
        else:
            typer.echo(f"Successful pull. Pulled to new file: {file}")
    
    
    
    
    
    
    
    
    
    