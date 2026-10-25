import asyncio
from pathlib import Path

from cryptography.fernet import InvalidToken
from pydantic import ValidationError, BaseModel
import typer

from pas_app.adapters.promts import cli_password_promt
from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import MessageResponse, PullRequestData, PullResponse, PullStatuses, PushRequestData, PushResponse, PushStatuses, VaultsDataResponse
from pas_app.dependencies import get_logger, get_keyring_tool
from pas_app.schemas.vaults import EncryptedUserVault, VaultData
from pas_app.services.file_utils import get_user_vault_files, load_encrypted_vault_by_path
from pas_app.core.crypto import (
    create_random_salt, 
    decrypt_vault_passwords, 
    derive_key,
    decrypt_dek
)

logger = get_logger()
api = Api()
keyring = get_keyring_tool()

async def _pull(
    payload: PullRequestData,
    file_path: Path | None
):
    keyring_data = keyring.load()
    response = await api.pull_vault(payload=payload)
    
    if isinstance(response.content, MessageResponse) and not isinstance(response.content, PullResponse):
        typer.echo(response.content.detail)
        return

    if not isinstance(response.content, PullResponse):
        typer.echo("Wrong server response type")
        return

    status = response.content.status

    if status == PullStatuses.NOT_FOUND:
        typer.echo("Vault not found on server")

    elif status == PullStatuses.LOCAL_AHEAD:
        typer.echo("Local version is newer than server version.\nPush first or use '--force' to overwrite local file")

    elif status == PullStatuses.UP_TO_DATE:
        typer.echo("Vault is already up to date with server.")
    elif status == PullStatuses.PULLED:
        vault_data = response.content.vault_data
        if not vault_data:
            typer.echo("Server returned PULLED status, but vault data is missing")
            return

        # Сохраняем обновленные данные в локальный файл
        if file_path is None:
            user_dir = VAULTS / keyring_data.current_user
            user_dir.mkdir(exist_ok=True)
            file_path = user_dir / f'{vault_data.name}_v{vault_data.version}.json'
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(vault_data.model_dump_json(indent=4))

        if payload.force:
            typer.echo("Forced pull...")
        typer.echo(f"Successful pull. Pulled to file: {file_path}")
        

async def _push(payload: PushRequestData, path: Path): # add here path_file!
    response = await api.push_vault(payload=payload)
    if isinstance(response.content, MessageResponse):
        typer.echo(response.content.detail)
        return
    
    if not isinstance(response.content, PushResponse):
        typer.echo("Wrong server response type")
        return
    
    status = response.content.status
    if status == PushStatuses.NOT_FOUND:
        typer.echo("Vault not found")
    elif status == PushStatuses.OUTDATED:
        typer.echo("Server has higher version of vault.\nUse '--force' to force push request")
    elif status == PushStatuses.UP_TO_DATE:
        typer.echo("Server has the same version of vault.\nUse '--force' to force push request")
    elif status == PushStatuses.OVERWRITTEN:
        typer.echo("Successful push. Server version was overwrotten")
    elif status == PushStatuses.PUSHED:
        typer.echo("Successful push.")
    elif status == PushStatuses.CREATED:
        
        encrypted = EncryptedUserVault(
            id=response.content.vault_id,
            name=payload.name,
            salt=payload.salt,
            encrypted_dek=payload.encrypted_dek,
            encrypted_passwords=payload.encrypted_passwords,
            version=payload.version
        )
        try:
            with open(path, "w", encoding='utf-8') as f:
                f.write(encrypted.model_dump_json(indent=4))
        except Exception as e:
            typer.echo(f"Saving error of vault: {path}")
            logger.error(e)
            return
                    
        typer.echo("Successful push with saving vault on the server.")


async def sync_vaults():
    keyring_data = keyring.load()
    response = await api.get_vaults()
    username = keyring_data.current_user
    if not isinstance(response.content, VaultsDataResponse):
        if isinstance(response.content, MessageResponse):
            logger.error(f"Failed to fetch vaults: {response.content.detail}")
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        else:
            logger.error(f"Unexpected response type on get_vaults: {type(response.content)}")
            typer.echo("Wrong content from api")
            raise typer.Exit(code=1)
    
    server_vaults = response.content.vaults
        
    if not server_vaults:
        logger.info("No vaults to pull")
        typer.echo("You have no vaults to pull")

    server_map = {v.id: v for v in server_vaults}
    local_map = {}
    pull_queue: list[tuple[PullRequestData, Path | None]] = []
    push_queue: list[tuple[PushRequestData, Path]] = []
    push_paths: list[Path] = []
    for local_file in get_user_vault_files(username=username):
        encrypted = await load_encrypted_vault_by_path(path=local_file)
        if encrypted == None:
            continue
        
        if encrypted.id == None:
            push_paths.append(local_file)
        else:
            local_map[encrypted.id] = (encrypted, local_file)


    for local_id, (local_vault, local_path) in local_map.items():
        local_vault: EncryptedUserVault
        if local_id not in server_map: # такого vault_id нет на сервере значит делаем push
            push_paths.append(local_path)
        else:
            server_vault = server_map[local_id]
            if server_vault.version > local_vault.version: # версия с сервера больше чем локальная значит делаем pull
                pull_queue.append(
                    (PullRequestData(
                        vault_id=local_id,
                        version=local_vault.version,
                        force=False
                    ),
                    local_path)
                )
            elif server_vault.version < local_vault.version: # версия с сервера меньше чем локальная значит делаем push
                push_paths.append(local_path)
            else: # весия с сервера равна локальной значит ничего не делаем просто сообщаем о том что версия совпадает
                typer.echo(f"Vault '{local_vault.name}' is already up to date (v1.{local_vault.version})")
                
    for server_id in server_map.keys():
        if server_id not in local_map:
            pull_queue.append((
                PullRequestData(
                    vault_id=server_id,
                    version=None,
                    force=True
                ),
                None
            ))

    
    # делаем pull
    for (payload, vault_path) in pull_queue:
        await _pull(payload=payload, file_path=vault_path)
    
    # делаем push
    def _unlock_vault(encrypted_vault: EncryptedUserVault):
        typer.echo(f"\nEnter master password to unlock vault: {encrypted_vault.name}")
        vault_master_password = cli_password_promt()
        kek = derive_key(vault_master_password, encrypted_vault.salt)
        dek = decrypt_dek(kek=kek, encrypted_dek_str=encrypted_vault.encrypted_dek)
    
        # attempt to decrypt (if wrong master password raises InvalidToken)
        passwords = decrypt_vault_passwords(encrypted_passwords=encrypted_vault.encrypted_passwords, key=dek)
        return PushRequestData(
            id=encrypted_vault.id,
            name=encrypted_vault.name,
            salt=encrypted_vault.salt,
            entries=len(passwords.passwords),
            encrypted_dek=encrypted_vault.encrypted_dek,
            encrypted_passwords=encrypted_vault.encrypted_passwords,
            version=encrypted_vault.version,
            force=False
        )
    
    for path in push_paths:
        encrypted = await load_encrypted_vault_by_path(path=path)
        if encrypted == None:
            continue
        
        
        unlocked = False
        for attempt in range(1, 4):
            try:
                push_request_data = _unlock_vault(encrypted_vault=encrypted)
            except InvalidToken:
                typer.echo("Wrong master password for this vault")
                typer.echo(f"{3 - attempt} attempts left")
                continue
            unlocked = True
            push_queue.append((push_request_data, path))
            break
        if not unlocked:
            typer.echo("Too much wrong attempts, skipping...\n")
            continue
    
    for (payload, path) in push_queue:
        await _push(payload=payload, path=path)