import typer

from pas_app.adapters.promts import choose_current_vault
from pas_app.services.file_utils import get_VaultPringData, get_user_vault_files
from pas_app.dependencies import get_keyring_tool
from pas_app.dependencies import get_logger
# add logging!

logger = get_logger()

def select_current_vault():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    username = keyring_data.current_user
    vaults = get_user_vault_files(username=username)
    logger.debug(f"DEBUG:\nvaults={vaults}\n")
    if not vaults:
        typer.echo("You have no vaults to select.\nCreate a new one")
        raise typer.Exit(code=1)
    data = get_VaultPringData(vaults=vaults)
    logger.debug(f"data={data}")
    selected = choose_current_vault(data=data, current_vault=keyring_data.current_vault)
    if keyring_data.current_user != selected:
        keyring_data.master_password = ""
    keyring_data.current_vault = selected
    keyring.save(data=keyring_data)
    
    typer.echo(f"Current vault was successfully set as {selected}")