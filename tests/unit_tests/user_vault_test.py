from pathlib import Path

from pas_app.config import UserConfig
from pas_app.schemas.passwords import UserVault, Password
from pas_app.services.password import load_encrypted_vault
from pas_app.services.file_utils import (
    save_data, 
    load_data,
    create_vault
)


def test_create_user_vault(monkeypatch, tmp_path, test_username, test_vault_name):
    monkeypatch.setattr("pas_app.services.file_utils.VAULTS", tmp_path)
    monkeypatch.setattr("pas_app.services.file_utils.select_new_vault_name", lambda: test_vault_name)
    monkeypatch.setattr("pas_app.services.file_utils.select_master_password", lambda: "admin")

    create_vault(test_username)
    test_vault = tmp_path / test_username / "Vault.json"

    assert test_vault.exists()
    
def test_user_vault_start_data(monkeypatch, tmp_path: Path, test_username: str, test_vault_name: str):
    monkeypatch.setattr("pas_app.services.file_utils.VAULTS", tmp_path)
    monkeypatch.setattr("pas_app.services.file_utils.select_new_vault_name", lambda: test_vault_name)
    monkeypatch.setattr("pas_app.services.file_utils.select_master_password", lambda: "admin")

    create_vault(test_username)
    
    enctypted = load_encrypted_vault(username=test_username, vault_name=test_vault_name)
    
    assert enctypted.username == test_username
    assert enctypted.salt is not None and type(enctypted.salt) == str
    assert enctypted.encrypted_dek is not None and type(enctypted.encrypted_dek) == str
    assert enctypted.encrypted_passwords == ""
    
    
    

