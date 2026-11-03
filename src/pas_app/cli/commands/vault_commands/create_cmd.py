import typer

from pas_app.dependencies import get_keyring_tool, get_logger
from pas_app.schemas.api import CreateVaultDataRequest, CreateVaultResponse, MessageResponse
from pas_app.services.file_utils import create_vault, load_encrypted_vault, create_vault_path
from pas_app.core.api import Api
from pas_app.adapters.promts import (
    select_vault_name,
    select_master_password
)

logger = get_logger()


def create_vault_offline():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    username = keyring_data.current_user

    logger.info(f"Starting offline vault creation for user '{username}'")
    vault_name = select_vault_name()
    master_password = select_master_password()

    try:
        create_vault(username=username, vault_name=vault_name, master_password=master_password)
    except FileExistsError as e:
        logger.warning(f"Offline vault creation aborted: vault '{vault_name}' already exists")
        typer.echo(f'\n[ERROR] {e}\n')
        raise typer.Exit(code=1)

    logger.info(f"Offline vault '{vault_name}' successfully created")
    typer.echo("\nNew vault was successfully created\n")
    raise typer.Exit(code=0)


async def create_vault_online():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    username = keyring_data.current_user

    logger.info(f"Starting online vault creation for user '{username}'")
    vault_name = select_vault_name()
    master_password = select_master_password()

    try:
        create_vault(username=username, vault_name=vault_name, master_password=master_password)
    except FileExistsError:
        logger.warning(f"Online vault creation aborted: local file for '{vault_name}' already exists")
        typer.echo("\nVault with this name already exists\nPlease, choose another one\n")
        raise typer.Exit(code=1)

    encrypted = load_encrypted_vault(username=username, vault_name=vault_name)
    payload = CreateVaultDataRequest(
        name=encrypted.name,
        salt=encrypted.salt,
        encrypted_dek=encrypted.encrypted_dek,
    )

    api = Api()
    logger.debug(f"Sending remote vault creation request for '{vault_name}'")
    response = await api.create_vault(payload=payload)

    if response.status_code == 201:
        assert isinstance(response.content, CreateVaultResponse)
        created_vault_path = create_vault_path(username=username, vault_name=vault_name)
        if not created_vault_path.exists():
            logger.error(f"Local file missing after creation: {created_vault_path}")
            typer.echo("\nUnexpected error, vault not created\n")
            raise typer.Exit(code=1)

        encrypted.id = response.content.vault_id

        with open(created_vault_path, 'w', encoding='utf-8') as f:
            f.write(encrypted.model_dump_json(indent=4))

        logger.info(f"Vault '{vault_name}' registered remotely (ID: {response.content.vault_id}) and synced locally")
        typer.echo("\nNew vault was successfully created\n")
        raise typer.Exit(code=0)
    else:
        assert isinstance(response.content, MessageResponse)
        logger.error(f"Remote creation failed (HTTP {response.status_code}): {response.content.detail}")
        typer.echo(response.content.detail)
    
    
    