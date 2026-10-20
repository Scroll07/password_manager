import time

import typer

from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import ApiResponse, DownloadResponse, MessageResponse, VaultsDataResponse
from pas_app.schemas.vaults import VaultData
from pas_app.adapters.promts import (
    print_and_choose_vault,
    choose_action,
    choose_name_for_vault,
    cli_password_promt,
    clear_console
)
from pas_app.dependencies import get_keyring_tool




async def check_status_unlock_vault(vault: VaultData) -> None:
    api = Api()
    
    response = await api.get_vault_status(vault_id=vault.id)
    if response.status_code != 200:
    
        async def unlock_vault() -> ApiResponse:
            clear_console()
            typer.echo("Enter master password to unlock vault")
            vault_master_password = cli_password_promt()
            response = await api.unlock_vault(
                vault_id=vault.id,
                vault_master_password=vault_master_password
            )
            return response

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            unlock_response = await unlock_vault()
            if unlock_response.status_code == 200:
                return None
            else:
                remaining = max_attempts - attempt
                typer.echo(f"Wrong master password, remaining attempts: {remaining}")
                time.sleep(2)
        else:
            typer.echo("Wrong master passwords, exiting...")
            raise typer.Exit(code=1)                

    

async def delete(vault: VaultData):
    await check_status_unlock_vault(vault=vault)

    api = Api()

    response = await api.delete_vault(vault_id=vault.id)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Get vault failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    typer.echo(response.content.detail)

async def download(vault: VaultData):
    await check_status_unlock_vault(vault=vault)

    api = Api()
    
    response = await api.download_vault(vault_id=vault.id)
    if response.status_code != 200:
        assert isinstance(response.content, MessageResponse)
        typer.echo(response.content.detail)
        raise typer.Exit(code=1)
    
    assert isinstance(response.content, DownloadResponse)
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    vault_file = VAULTS / keyring_data.current_user / response.content.filename
    with open(vault_file, 'w', encoding='utf-8') as f:
        f.write(response.content.vault_data.model_dump_json(indent=4))
        
    typer.echo(f"Downloaded new vault file: {vault_file}")


async def rename(vault: VaultData):
    await check_status_unlock_vault(vault=vault)

    api = Api()

    new_name = choose_name_for_vault()
    response = await api.rename_vault(vault_id=vault.id, new_vault_name=new_name)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Rename vault failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    typer.echo(response.content.detail)


async def change_pin(vault: VaultData):
    await check_status_unlock_vault(vault=vault)

    api = Api()

    response = await api.change_pin_vault(vault_id=vault.id)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Rename vault failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    typer.echo(response.content.detail)





# ==========================
        #FUNC FOR TYPER
# ==========================
async def vaults_acions():
    api = Api()
    while True:
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
            typer.echo("You have not vaults")
            raise typer.Exit(code=0)
        
        vault = print_and_choose_vault(vaults=vaults, text="Choose backup for action")
        choice = choose_action(vault=vault)
        
        if choice == "cancel":
            typer.echo("Cancel")
            continue
        elif choice == "download":
            await download(vault=vault)
        elif choice == "change-pin":
            await change_pin(vault=vault)
        elif choice == "rename":
            await rename(vault=vault)
        elif choice == "delete":
            await delete(vault=vault)