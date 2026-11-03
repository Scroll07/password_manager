import typer

from pas_app.adapters.promts import print_and_choose_vault
from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import MessageResponse, PullRequestData, PullResponse, PullStatuses, VaultsDataResponse
from pas_app.services.file_utils import (
    load_encrypted_vault,
    create_vault_path
)
from pas_app.dependencies import get_keyring_tool, get_logger

logger = get_logger()


async def pull_vault(
    force: bool,
    create_new_file: bool
):
    api = Api()
    logger.debug("Requesting vaults list from server for pull")
    response = await api.get_vaults()
    if not isinstance(response.content, VaultsDataResponse):
        if isinstance(response.content, MessageResponse):
            logger.error(f"Failed to fetch vaults: {response.content.detail}")
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        else:
            logger.error(f"Unexpected response type from get_vaults: {type(response.content)}")
            typer.echo("Wrong content from api")
            raise typer.Exit(code=1)
    
    vaults = response.content.vaults
    if not vaults:
        logger.info("No remote vaults found on server")
        typer.echo("You have no vaults")
        raise typer.Exit(code=0)

    vault = print_and_choose_vault(vaults=vaults, text="Choose vault to pull")
    logger.info(f"Selected vault '{vault.name}' (ID: {vault.id}) for pull")
    
    # find vault with such name to get version
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    file = create_vault_path(username=keyring_data.current_user, vault_name=vault.name)
    version = None
    if file.exists():
        encrypted_data = load_encrypted_vault(username=keyring_data.current_user, vault_name=vault.name)
        version = encrypted_data.version
        logger.debug(f"Found local file for '{vault.name}', local version: v1.{version}")
    else:
        logger.debug(f"No existing local file for '{vault.name}'")
    
    request_data = PullRequestData(
        vault_id=vault.id,
        version=version,
        force=force
    )
    logger.info(f"Sending pull request for vault ID {vault.id} (local version: {version}, force: {force})")
    response = await api.pull_vault(payload=request_data)

    if not isinstance(response.content, PullResponse):
        if type(response.content) is MessageResponse:
            logger.error(f"Pull failed for vault ID {vault.id}: {response.content.detail}")
            typer.echo(f"  [ERROR]: {response.content.detail}")
        else:
            logger.error(f"Unexpected response type for pull: {type(response.content)}")
            typer.echo("  [ERROR]: Wrong server response type")
        raise typer.Exit(code=1)

    status = response.content.status

    if status == PullStatuses.NOT_FOUND:
        logger.warning(f"Vault ID {vault.id} not found on server")
        typer.echo("Vault not found on server")
        raise typer.Exit(code=1)

    elif status == PullStatuses.LOCAL_AHEAD:
        logger.warning(f"Pull rejected: local version of vault ID {vault.id} is ahead of server")
        typer.echo("Local version is newer than server version.\nPush first or use '--force' to overwrite local file")
        raise typer.Exit(code=1)

    elif status == PullStatuses.UP_TO_DATE:
        logger.info(f"Vault '{vault.name}' (ID: {vault.id}) is already up to date")
        typer.echo("Vault is already up to date with server.")
        return

    elif status == PullStatuses.PULLED:
        vault_data = response.content.vault_data
        if not vault_data:
            logger.error(f"Server returned PULLED status for vault ID {vault.id}, but vault_data is missing")
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

        logger.info(f"Successfully pulled vault '{vault_data.name}' (v1.{vault_data.version}) to '{file.name}'")

        if force:
            typer.echo("Forced pull...")
        if not create_new_file:
            typer.echo("Successful pull. Local changes were overwritten")
        else:
            typer.echo(f"Successful pull. Pulled to new file: {file}")
    
    
    
    
    
    
    
    
    
    