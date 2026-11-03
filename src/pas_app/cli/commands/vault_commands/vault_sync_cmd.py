from pathlib import Path
from cryptography.fernet import InvalidToken
import typer

from pas_app.adapters.promts import cli_password_promt
from pas_app.core.api import Api
from pas_app.core.settings import VAULTS
from pas_app.schemas.api import (
    MessageResponse, 
    PullRequestData, 
    PullResponse, 
    PullStatuses, 
    PushRequestData, 
    PushResponse, 
    PushStatuses,
    VaultsDataResponse
)
from pas_app.dependencies import get_logger, get_keyring_tool
from pas_app.schemas.vaults import EncryptedUserVault
from pas_app.services.file_utils import get_user_vault_files, load_encrypted_vault_by_path
from pas_app.core.crypto import (
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
    logger.info(f"Initiating pull for vault ID {payload.vault_id}")
    typer.echo(f"\n[PULL] Checking vault (ID: {payload.vault_id})...")
    response = await api.pull_vault(payload=payload)
    
    if not isinstance(response.content, PullResponse):
        if type(response.content) is MessageResponse:
            logger.error(f"Pull failed for vault ID {payload.vault_id}: {response.content.detail}")
            typer.echo(f"  [ERROR] Vault ID {payload.vault_id}: {response.content.detail}")
        else:
            logger.error(f"Unexpected response type for pull of vault ID {payload.vault_id}: {type(response.content)}")
            typer.echo(f"  [ERROR] Vault ID {payload.vault_id}: Wrong server response type")
        return

    status = response.content.status

    if status == PullStatuses.NOT_FOUND:
        logger.warning(f"Vault ID {payload.vault_id} was not found on server")
        typer.echo(f"  [NOT FOUND] Vault ID {payload.vault_id} was not found on server")

    elif status == PullStatuses.LOCAL_AHEAD:
        logger.warning(f"Pull skipped: local version of vault ID {payload.vault_id} is ahead of server")
        typer.echo(
            f"  [LOCAL AHEAD] Local version of vault ID {payload.vault_id} is newer than server version.\n"
            f"  Push first or use '--force' to overwrite local file"
        )

    elif status == PullStatuses.UP_TO_DATE:
        logger.info(f"Vault ID {payload.vault_id} is already up to date with server")
        typer.echo(f"  [UP TO DATE] Vault ID {payload.vault_id} is already up to date with server.")

    elif status == PullStatuses.PULLED:
        vault_data = response.content.vault_data
        if not vault_data:
            logger.error(f"Server returned PULLED status for vault ID {payload.vault_id}, but vault_data is missing")
            typer.echo(f"  [ERROR] Server returned PULLED status for vault ID {payload.vault_id}, but vault data is missing")
            return

        # Сохраняем обновленные данные в локальный файл
        if file_path is None:
            user_dir = VAULTS / keyring_data.current_user
            user_dir.mkdir(exist_ok=True)
            file_path = user_dir / f'{vault_data.name}_v{vault_data.version}.json'
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(vault_data.model_dump_json(indent=4))

        logger.info(f"Successfully pulled vault '{vault_data.name}' (v{vault_data.version}) into '{file_path.name}'")
        if payload.force:
            typer.echo(f"  [FORCED] Overwriting local file with server version...")
        typer.echo(f"  [SUCCESS] Successfully pulled '{vault_data.name}' (v{vault_data.version}) -> {file_path.name}")
        

async def _push(payload: PushRequestData, path: Path):
    vault_name = f"'{payload.name}'"
    logger.info(f"Initiating push for vault {vault_name} from '{path.name}'")
    typer.echo(f"\n[PUSH] Sending {vault_name} ({path.name})...")
    
    response = await api.push_vault(payload=payload)
    
    if not isinstance(response.content, PushResponse):
        if type(response.content) is MessageResponse:
            logger.error(f"Push failed for {vault_name}: {response.content.detail}")
            typer.echo(f"  [ERROR] {vault_name}: {response.content.detail}")
        else:
            logger.error(f"Unexpected response type for push of {vault_name}: {type(response.content)}")
            typer.echo(f"  [ERROR] {vault_name}: Wrong server response type")
        return

    status = response.content.status
    if status == PushStatuses.NOT_FOUND:
        logger.warning(f"Push rejected: vault {vault_name} not found on server")
        typer.echo(f"  [NOT FOUND] Vault {vault_name} not found on server")
    elif status == PushStatuses.OUTDATED:
        logger.warning(f"Push rejected: server has higher version of {vault_name}")
        typer.echo(
            f"  [OUTDATED] Server has higher version of {vault_name}.\n"
            f"  Use '--force' to force push request"
        )
    elif status == PushStatuses.UP_TO_DATE:
        logger.info(f"Push skipped: server already has identical version of {vault_name}")
        typer.echo(
            f"  [UP TO DATE] Server already has the same version of {vault_name}.\n"
            f"  Use '--force' to force push request"
        )
    elif status == PushStatuses.OVERWRITTEN:
        logger.info(f"Server version of {vault_name} was overwritten successfully")
        typer.echo(f"  [SUCCESS] Server version of {vault_name} was overwritten successfully")
    elif status == PushStatuses.PUSHED:
        logger.info(f"Successfully pushed {vault_name} (v{payload.version})")
        typer.echo(f"  [SUCCESS] Successfully pushed {vault_name} (v{payload.version})")
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
            logger.error(f"Failed to save updated vault {vault_name} locally to '{path.name}': {e}")
            typer.echo(f"  [ERROR] Failed to save updated vault {vault_name} locally: {path.name}")
            return
                    
        logger.info(f"Created remote vault {vault_name} (assigned ID: {response.content.vault_id}) and updated '{path.name}'")
        typer.echo(f"  [SUCCESS] Created new remote vault {vault_name} (assigned ID: {response.content.vault_id}) and updated {path.name}")


async def sync_vaults():
    keyring_data = keyring.load()
    username = keyring_data.current_user
    logger.info(f"Starting synchronization process for user '{username}'")

    response = await api.get_vaults()
    if not isinstance(response.content, VaultsDataResponse):
        if isinstance(response.content, MessageResponse):
            logger.error(f"Failed to fetch vaults for sync: {response.content.detail}")
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        else:
            logger.error(f"Unexpected response type on get_vaults: {type(response.content)}")
            typer.echo("Wrong content from api")
            raise typer.Exit(code=1)
    
    server_vaults = response.content.vaults
        
    if not server_vaults:
        logger.info(f"No remote vaults found on server for user '{username}'")
        typer.echo("You have no vaults to pull")

    server_map = {v.id: v for v in server_vaults}
    local_map = {}
    pull_queue: list[tuple[PullRequestData, Path | None]] = []
    push_queue: list[tuple[PushRequestData, Path]] = []
    push_paths: list[Path] = []

    for local_file in get_user_vault_files(username=username):
        encrypted = await load_encrypted_vault_by_path(path=local_file)
        if encrypted is None:
            continue
        
        if encrypted.id is None:
            push_paths.append(local_file)
        else:
            local_map[encrypted.id] = (encrypted, local_file)

    for local_id, (local_vault, local_path) in local_map.items():
        local_vault: EncryptedUserVault
        if local_id not in server_map:  # такого vault_id нет на сервере, значит делаем push
            push_paths.append(local_path)
        else:
            server_vault = server_map[local_id]
            if server_vault.version > local_vault.version:  # версия сервера новее, делаем pull
                pull_queue.append(
                    (PullRequestData(
                        vault_id=local_id,
                        version=local_vault.version,
                        force=False
                    ),
                    local_path)
                )
            elif server_vault.version < local_vault.version:  # локальная версия новее, делаем push
                push_paths.append(local_path)
            else:
                logger.info(f"Vault '{local_vault.name}' is up to date (v1.{local_vault.version})")
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

    logger.info(f"Sync queues formed: {len(pull_queue)} pull tasks, {len(push_paths)} candidate vaults to push")
    
    # делаем pull
    for (payload, vault_path) in pull_queue:
        await _pull(payload=payload, file_path=vault_path)
    
    # делаем push
    def _unlock_vault(encrypted_vault: EncryptedUserVault):
        typer.echo(f"\nUnlock vault ({encrypted_vault.name}) to send a [PUSH] request")
        vault_master_password = cli_password_promt(f"Enter master password to unlock vault {encrypted_vault.name}: ")
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
        if encrypted is None:
            continue
        
        unlocked = False
        for attempt in range(1, 4):
            try:
                push_request_data = _unlock_vault(encrypted_vault=encrypted)
            except InvalidToken:
                logger.warning(f"Failed unlock attempt {attempt}/3 for vault '{encrypted.name}' ({path.name})")
                typer.echo("Wrong master password for this vault")
                typer.echo(f"{3 - attempt} attempts left")
                continue
            unlocked = True
            logger.info(f"Vault '{encrypted.name}' successfully unlocked for push")
            push_queue.append((push_request_data, path))
            break
        if not unlocked:
            logger.error(f"Failed to unlock vault '{encrypted.name}' after 3 attempts, skipping push")
            typer.echo("Too much wrong attempts, skipping...\n")
            continue
    
    for (payload, path) in push_queue:
        await _push(payload=payload, path=path)

    logger.info(f"Synchronization finished for user '{username}'")