from pathlib import Path
import pytest

from pas_app.config import (
    UserConfig,
    ConfigData
)


def test_create_config(config: UserConfig, tmp_path: Path):
    config_file = tmp_path / "test_config.json"
    assert not config_file.exists()
    
    config.create_empty_config()
    assert config_file.exists()

    with open(config_file, "r", encoding="utf-8") as f:
        data = f.read()
    
    local_data = ConfigData.model_validate_json(data, strict=True)
    
    assert local_data.BOT_TOKEN == "no token"
    assert local_data.BASE_URL == "http://localhost:80"
    assert local_data.COLLECT_STATISTIC == True    

def test_save_values_after_recreate_config(config: UserConfig):
    test_data = {
        "BOT_TOKEN": "123456789",
        "BASE_URL": "https:google.com:80",
        "COLLECT_STATISTIC": False
    }
    config.create_empty_config()
    config_data = config.load_config()

    config_data.BOT_TOKEN = test_data['BOT_TOKEN']
    config_data.BASE_URL = test_data['BASE_URL']
    config_data.COLLECT_STATISTIC = test_data['COLLECT_STATISTIC']
    config.save_config(data=config_data)
    
    config.create_empty_config()
    
    config_data = config.load_config()
    assert config_data.BOT_TOKEN == test_data['BOT_TOKEN']
    assert config_data.BASE_URL == test_data['BASE_URL']
    assert config_data.COLLECT_STATISTIC == test_data['COLLECT_STATISTIC']
    
    
