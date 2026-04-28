import pytest

from pas_app.cli.commands.pas_commands.add import add_command
from pas_app.schemas.passwords import Password, UserVault
from pas_app.services.file_utils import save_data, load_data


def test_add_command(
    test_vault: UserVault,
    test_username,
    state    
):
    passwords = [
        Password(
            service="gmail",
            username="mytest@gmail.com",
            password="secret_password",
            note="my gmail"
        ),
        Password(
            service="game",
            username="mytest@gmail.com",
            password="secret_password",
            note="my game"
        ),
        Password(
            service="tik tok",
            username="tik tok accaunt",
            password="secret_password",
            note="my tik tok"
        ),
    ]
    
    vault_data = UserVault(
        username=test_username,
        salt=test_vault.salt,
        user_passwords=passwords
    )
    save_data(state=state, vault_data=vault_data)
    
    loaded_data = load_data(state)
    
    assert loaded_data == vault_data
    
    
    



