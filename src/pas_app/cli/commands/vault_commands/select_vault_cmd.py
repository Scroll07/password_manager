import typer

from pas_app.adapters.promts import choose_current_vault
from pas_app.services.file_utils import get_VaultPringData, get_user_vault_files
from pas_app.dependencies import get_keyring_tool, get_logger

logger = get_logger()


def select_current_vault():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    logger.info(f"Initiating active vault selection for user '{username}'")

    vaults = get_user_vault_files(username=username)
    if not vaults:
        logger.warning(f"No local vaults found for user '{username}'")
        typer.echo("You have no vaults to select.\nCreate a new one with: 'pas vault create'")
        raise typer.Exit(code=1)

    data = get_VaultPringData(vaults=vaults)
    selected = choose_current_vault(data=data, current_vault=keyring_data.current_vault)

    # Исправлена проверка: сравниваем с current_vault, а не с current_user
    if keyring_data.current_vault != selected:
        logger.info(
            f"Active vault changed from '{keyring_data.current_vault}' to '{selected}', resetting session password"
        )
        keyring_data.master_password = ""

    keyring_data.current_vault = selected
    keyring.save(data=keyring_data)

    logger.info(f"Successfully updated keyring: active vault set to '{selected}'")
    typer.echo(f"Current vault was successfully set as {selected}")