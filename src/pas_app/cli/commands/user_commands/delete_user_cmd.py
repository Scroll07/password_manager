import typer

from pas_app.config import VAULTS
from pas_app.adapters.promts import choose_delete_user
from pas_app.services.file_utils import get_vault_usernames


def delete_user():
    """
    Delete a local vault user.

    The command deletes only the local vault file for the selected user.
    It does not remove the user from the server.

    Examples:
        pas user delete

    After running the command, choose a user from the list and confirm
    the deletion prompt.
    """
    usernames = get_vault_usernames()
    username = choose_delete_user(usernames=usernames)
    user_file = VAULTS / f"{username}.json"
    if not user_file.exists():
        typer.echo(f"File {user_file} does not exist")
        return
    if not typer.confirm(f"Delete user: {username}?"):
        typer.echo(f"Deleting was canceled")
        return
    
    user_file.unlink()
    typer.echo(f"User {username} was successfully deleted")
    