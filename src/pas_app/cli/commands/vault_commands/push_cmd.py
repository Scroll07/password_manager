

from cryptography.fernet import InvalidToken
import typer

from pas_app.adapters.promts import choose_vault
from pas_app.core.api import Api
from pas_app.core.crypto import decrypt_vault_passwords
from pas_app.schemas.api import MessageResponse, PushResponse, PushStatuses, PushRequestData
from pas_app.schemas.vaults import EncryptedUserVault
from pas_app.services.file_utils import (
    get_user_vault_files,
    load_encrypted_vault
)
from pas_app.dependencies import get_keyring_tool, get_logger
from pas_app.services.password import get_key

logger = get_logger()


async def push_vault(
    force: bool
):
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    
    vault_files = get_user_vault_files(username=username)
    vault_file = choose_vault(vaults=vault_files, msg="Choose vault to push")
    logger.info(f"Selected vault file '{vault_file.name}' for push")
    
    try:
        with open(vault_file, "r") as f:
            data = f.read()
        encrypted = EncryptedUserVault.model_validate_json(data)
    except Exception as e:
        logger.error(f"Failed to parse vault file '{vault_file.name}': {e}")
        typer.echo("Vault file has wrong structure or broken")
        raise typer.Exit(code=1)
    
    try:
        key = get_key()
    except InvalidToken:
        logger.warning(f"Master password verification failed for '{vault_file.name}'")
        typer.echo("Wrong master password")
        raise typer.Exit(code=1)
    
    decoded_passwords = decrypt_vault_passwords(encrypted.encrypted_passwords, key)
    entries_count = len(decoded_passwords.passwords)
    
    if force:
        logger.warning(f"Pushing vault '{encrypted.name}' with --force enabled")
        typer.confirm(
            "⚠️  Warning: You are using the --force flag. "
            "The vault data on the server will be irreversibly overwritten! Continue?",
            abort=True
        )
    
    api = Api()
    request_data = PushRequestData(
        id=encrypted.id,
        name=encrypted.name,
        salt=encrypted.salt,
        entries=entries_count,
        encrypted_dek=encrypted.encrypted_dek,
        encrypted_passwords=encrypted.encrypted_passwords,
        version=encrypted.version,
        force=force
    )
    
    logger.info(
        f"Sending push request for vault '{encrypted.name}' "
        f"(ID: {encrypted.id}, version: {encrypted.version}, entries: {entries_count})"
    )
    response = await api.push_vault(payload=request_data)
    
    if not isinstance(response.content, PushResponse):
        if type(response.content) is MessageResponse:
            logger.error(f"Push failed for vault '{encrypted.name}': {response.content.detail}")
            typer.echo(f"  [ERROR]: {response.content.detail}")
        else:
            logger.error(f"Unexpected response type from push_vault: {type(response.content)}")
            typer.echo("  [ERROR]: Wrong server response type")
        raise typer.Exit(code=1)
    
    status = response.content.status

    if status == PushStatuses.NOT_FOUND:
        logger.warning(f"Push rejected: vault '{encrypted.name}' (ID: {encrypted.id}) not found on server")
        typer.echo("Vault not found")
        raise typer.Exit(code=1)

    elif status == PushStatuses.OUTDATED:
        logger.warning(f"Push rejected: server has newer version of vault '{encrypted.name}'")
        typer.echo("Server has higher version of vault.\nUse '--force' to force push request")
        raise typer.Exit(code=1)

    elif status == PushStatuses.UP_TO_DATE:
        logger.info(f"Vault '{encrypted.name}' is already up to date on server")
        typer.echo("Server has the same version of vault.\nUse '--force' to force push request")

    elif status == PushStatuses.OVERWRITTEN:
        logger.info(f"Vault '{encrypted.name}' (v{encrypted.version}) was overwritten on server")
        typer.echo("Successful push. Server version was overwritten")

    elif status == PushStatuses.PUSHED:
        logger.info(f"Successfully pushed vault '{encrypted.name}' (v{encrypted.version})")
        typer.echo("Successful push.")    

    elif status == PushStatuses.CREATED:
        encrypted.id = response.content.vault_id
        try:
            with open(vault_file, "w", encoding='utf-8') as f:
                f.write(encrypted.model_dump_json(indent=4))
        except Exception as e:
            logger.error(f"Failed to update local file '{vault_file.name}' with server ID: {e}")
            typer.echo(e)
            raise typer.Exit(code=1)
        
        logger.info(
            f"Created remote vault '{encrypted.name}' (assigned ID: {response.content.vault_id}) "
            f"and updated local file '{vault_file.name}'"
        )
        typer.echo("Successful push with saving vault on the server.")

    
    
    
    
    
    
    
    