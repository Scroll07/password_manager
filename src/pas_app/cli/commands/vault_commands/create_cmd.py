import typer

from pas_app.dependencies import get_keyring_tool
from pas_app.services.file_utils import create_vault

# add logging!

def create_vault_command():
    """
    Dockstring
    """
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    assert keyring_data.current_user
    create_vault(username=keyring_data.current_user)
    typer.echo("New vault was successfully created")
