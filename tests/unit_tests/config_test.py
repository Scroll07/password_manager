from pathlib import Path

from pas_app.config import get_config, UserConfig, ConfigFileData, KeyringConfig


def test_create_config(config: UserConfig, tmp_path: Path, test_username: str ):
    config_file = tmp_path / "test_config.json"
    assert not config_file.exists()
    
    config.create_empty_config(current_user=test_username)

    assert config_file.exists()
    
    with open(config_file, "r", encoding="utf-8") as f:
        data = f.read()
    
    local_data = ConfigFileData.model_validate_json(data, strict=True)
    
    assert local_data.default_user == test_username
    assert local_data.BOT_TOKEN == "no token"
    # assert local_data.BASE_URL == 

def test_save_values_after_recreate_config(config: UserConfig, test_username: str, random_username: str):
    config.create_empty_config(current_user=test_username)
    config_data = config._refresh()
    
    config_data.local.default_user = random_username
    config_data.keyring.master_password = "password"
    
    config.save_config(data=config_data)
    
    config.create_empty_config(current_user=test_username)
    
    config_data = config._refresh()
    
    assert config_data.local.default_user == random_username
    assert config_data.keyring.master_password == "password"
    

def test_load_config(config: UserConfig, test_username: str):
    config.create_empty_config(current_user=test_username)    
    config_data = config.load_config()
    
    assert isinstance(config_data.local, ConfigFileData)
    assert isinstance(config_data.keyring, KeyringConfig)
    
