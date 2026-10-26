

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
    # assert current_username is not ''
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    
    vault_files = get_user_vault_files(username=username)
    vault_file = choose_vault(vaults=vault_files, msg="Choose vault to push")
    
    try:
        with open(vault_file, "r") as f:
            data = f.read()
        encrypted = EncryptedUserVault.model_validate_json(data)
    except Exception:
        typer.echo("Vault file has wrong structure or broken")
        raise typer.Exit(code=1)
    
    try:
        key = get_key()
    except InvalidToken:
        typer.echo("Wrong master password")
        raise typer.Exit(code=1)
    
    decoded_passwords = decrypt_vault_passwords(encrypted.encrypted_passwords, key)
    
    if force:
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
        entries=len(decoded_passwords.passwords),
        encrypted_dek=encrypted.encrypted_dek,
        encrypted_passwords=encrypted.encrypted_passwords,
        version=encrypted.version,
        force=force
    )
    response = await api.push_vault(payload=request_data)
    if not type(response.content) == PushResponse:
        typer.echo("Wrong server response type")
        raise typer.Exit(code=1)
    
    if isinstance(response.content, MessageResponse):
        typer.echo(response.content.detail)
        raise typer.Exit(code=1)
    
    
    status = response.content.status
    if status == PushStatuses.NOT_FOUND:
        typer.echo("Vault not found")
        raise typer.Exit(code=1)
    elif status == PushStatuses.OUTDATED:
        typer.echo("Server has higher version of vault.\nUse '--force' to force push request")
        raise typer.Exit(code=1)
    elif status == PushStatuses.UP_TO_DATE:
        typer.echo("Server has the same version of vault.\nUse '--force' to force push request")
    elif status == PushStatuses.OVERWRITTEN:
        typer.echo("Successful push. Server version was overwrotten")
    elif status == PushStatuses.PUSHED:
        typer.echo("Successful push.")    
    elif status == PushStatuses.CREATED:
        encrypted.id = response.content.vault_id
        try:
            with open(vault_file, "w", encoding='utf-8') as f:
                f.write(encrypted.model_dump_json(indent=4))
        except Exception as e:
            typer.echo(e)
            logger.error(e)
            raise typer.Exit(code=1)
        
        typer.echo("Successful push with saving vault on the server.")
    # СОХРАНИТЬ ИЗМЕНЕНИЯ ПОСЛЕ PUSH ЕСЛИ МЫ СОЗДАЛИ VAULT на СЕРВЕРЕ ТО НАДО СОХРАНИТЬ ID
    # + ДОБАВЬ НОВЫЙ СТАТУС "CREATED" с помощью коорого мы поймем что нужно сохранить id
    # + перенеси новосозданную логику в vault_sync!!!!!!!!!!!!!!!!!!!!
    
    
    
    
    
    
    
    