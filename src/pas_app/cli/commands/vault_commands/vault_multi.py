import asyncio

from pydantic import ValidationError
import typer

from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import ApiResponse, DeleteVaultResponse, DownloadResponse, MessageResponse, VaultsDataResponse
from pas_app.schemas.vaults import EncryptedUserVault, VaultData
from pas_app.adapters.promts import (
    print_and_choose_vault,
    choose_action,
    choose_name_for_vault,
    cli_password_promt,
    clear_console
)
from pas_app.dependencies import get_keyring_tool, get_logger
from pas_app.services.file_utils import get_user_vault_files

logger = get_logger()


async def check_status_unlock_vault(vault: VaultData) -> None:
    logger.info(f"Checking lock status for vault {vault.id} ('{vault.name}')")
    api = Api()
    
    response = await api.get_vault_status(vault_id=vault.id)
    if response.status_code != 200:
        logger.warning(f"Vault {vault.id} is locked. Prompting user for master password")
    
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
            logger.info(f"Attempting to unlock vault {vault.id} (attempt {attempt}/{max_attempts})")
            unlock_response = await unlock_vault()
            if unlock_response.status_code == 200:
                logger.info(f"Vault {vault.id} successfully unlocked")
                return None
            else:
                remaining = max_attempts - attempt
                logger.warning(f"Failed unlock attempt for vault {vault.id}. Remaining: {remaining}")
                typer.echo(f"Wrong master password, remaining attempts: {remaining}")
                await asyncio.sleep(2)
        else:
            logger.error(f"Exceeded max unlock attempts for vault {vault.id}")
            typer.echo("Wrong master passwords, exiting...")
            raise typer.Exit(code=1)                


async def delete(vault: VaultData):
    logger.info(f"Initiating deletion for vault {vault.id} ('{vault.name}')")
    await check_status_unlock_vault(vault=vault)

    api = Api()

    response = await api.delete_vault(vault_id=vault.id)
    if response.status_code != 200:
        assert isinstance(response.content, MessageResponse)
        logger.error(f"Server deletion failed for vault {vault.id}: {response.status_code} - {response.content.detail}")
        typer.echo(
            f"Get vault failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    if not isinstance(response.content, DeleteVaultResponse):
        logger.error(f"Unexpected API response type during delete: {type(response.content)}")
        typer.echo("Wrong server response type")
        raise typer.Exit(code=1)
    
    logger.info(f"Server deleted vault {vault.id}. Cleaning up local copy")
    typer.echo(response.content.detail)
    typer.echo("\nTrying to delete vault locally...")
    
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    vaults = get_user_vault_files(username=keyring_data.current_user)
    for v in vaults:
        try:
            with open(v, 'r', encoding='utf-8') as f:
                encrypted = EncryptedUserVault.model_validate_json(f.read())
        except ValidationError as e:
            logger.error(f"Validation error of file {v}\n{e}")
            typer.echo(f"Validation error of file {v}\nSkipping...\n")
            await asyncio.sleep(0.5)
            continue
        
        if encrypted.id == response.content.vault_id and encrypted.name == response.content.vault_name:
            v.unlink()
            logger.info(f"Deleted local vault file: {v}")
            typer.echo("\nVault was successfully deleted locally")
            raise typer.Exit(code=0)
        elif encrypted.id == response.content.vault_id:
            logger.warning(f"Found local vault matching id {encrypted.id} but distinct name: {v}")
            typer.echo("\nA vault with the same id of what you deleted on server was found, but with a distinct name")
            if typer.confirm("Delete this vault?"):
                v.unlink()
                logger.info(f"Deleted renamed local vault file: {v}")
                typer.echo("\nVault was successfully deleted locally")
                raise typer.Exit(code=0)

    else:
        logger.warning(f"Local vault file for vault {vault.id} was not found")
        typer.echo("Vault was not found locally")
        raise typer.Exit(code=1)    


async def download(vault: VaultData):
    logger.info(f"Initiating download for vault {vault.id} ('{vault.name}')")
    await check_status_unlock_vault(vault=vault)

    api = Api()
    
    response = await api.download_vault(vault_id=vault.id)
    if response.status_code != 200:
        assert isinstance(response.content, MessageResponse)
        logger.error(f"Download failed for vault {vault.id}: {response.status_code} - {response.content.detail}")
        typer.echo(response.content.detail)
        raise typer.Exit(code=1)
    
    assert isinstance(response.content, DownloadResponse)
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    vault_file = VAULTS / keyring_data.current_user / response.content.filename
    with open(vault_file, 'w', encoding='utf-8') as f:
        f.write(response.content.vault_data.model_dump_json(indent=4))
        
    logger.info(f"Vault {vault.id} saved to {vault_file}")
    typer.echo(f"Downloaded new vault file: {vault_file}")


async def rename(vault: VaultData):
    logger.info(f"Initiating rename for vault {vault.id} ('{vault.name}')")
    await check_status_unlock_vault(vault=vault)

    api = Api()

    new_name = choose_name_for_vault()
    logger.info(f"Renaming vault {vault.id} to '{new_name}'")
    response = await api.rename_vault(vault_id=vault.id, new_vault_name=new_name)
    if not isinstance(response.content, MessageResponse):
        logger.error(f"Unexpected response type on rename: {type(response.content)}")
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        logger.error(f"Rename failed for vault {vault.id}: {response.status_code} - {response.content.detail}")
        typer.echo(
            f"Rename vault failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    logger.info(f"Vault {vault.id} renamed successfully")
    typer.echo(response.content.detail)


async def change_pin(vault: VaultData):
    logger.info(f"Initiating PIN change for vault {vault.id}")
    await check_status_unlock_vault(vault=vault)

    api = Api()

    response = await api.change_pin_vault(vault_id=vault.id)
    if not isinstance(response.content, MessageResponse):
        logger.error(f"Unexpected response type on change_pin: {type(response.content)}")
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        logger.error(f"Change PIN failed for vault {vault.id}: {response.status_code} - {response.content.detail}")
        typer.echo(
            f"Change PIN failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    logger.info(f"PIN changed successfully for vault {vault.id}")
    typer.echo(response.content.detail)


# ==========================
# FUNC FOR TYPER
# ==========================
async def vaults_actions():
    logger.info("Starting vaults CLI action loop")
    api = Api()
    while True:
        response = await api.get_vaults()
        if not isinstance(response.content, VaultsDataResponse):
            if isinstance(response.content, MessageResponse):
                logger.error(f"Failed to fetch vaults: {response.content.detail}")
                typer.echo(response.content.detail)
                raise typer.Exit(code=1)
            else:
                logger.error(f"Unexpected response type on get_vaults: {type(response.content)}")
                typer.echo("Wrong content from api")
                raise typer.Exit(code=1)
        
        vaults = response.content.vaults
        if not vaults:
            logger.info("No vaults found for user")
            typer.echo("You have no vaults")
            raise typer.Exit(code=0)
        
        vault = print_and_choose_vault(vaults=vaults, text="Choose backup for action")
        choice = choose_action(vault=vault)
        logger.info(f"User selected action '{choice}' for vault {vault.id}")
        
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