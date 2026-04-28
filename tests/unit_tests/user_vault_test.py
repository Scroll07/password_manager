


from pas_app.schemas.passwords import UserVault, Password
from pas_app.services.password import create_user_vault
from pas_app.services.file_utils import save_data, load_data


def test_create_user_vault(monkeypatch, tmp_path, test_username):
    monkeypatch.setattr("pas_app.services.password.VAULTS", tmp_path)
    
    create_user_vault(test_username)
    test_vault = tmp_path / f"{test_username}.json"
    
    print("Directory: ", test_vault)
    assert test_vault.exists()
    
    
def test_save_data(test_username, state, monkeypatch, tmp_path):
    def mock_cli_input_password() -> str:
        return "test_password"
    
    monkeypatch.setattr("pas_app.services.password.cli_password_promt", mock_cli_input_password)
    monkeypatch.setattr("pas_app.services.password.VAULTS", tmp_path)
    monkeypatch.setattr("pas_app.services.file_utils.VAULTS", tmp_path)
    
    
    create_user_vault(test_username)
    
    loaded_vault = load_data(state=state)
    salt = loaded_vault.salt
    
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
        salt=salt,
        user_passwords=passwords
    )
    
    save_data(state=state, vault_data=vault_data)
    
    new_vault = load_data(state=state)
    
    assert new_vault == vault_data
    
    
    
    
    
    
    
    