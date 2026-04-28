import pytest

from pas_app.config import UserConfig, BASE_DIR, ConfigData



def test_create_config(config: UserConfig, random_username):
    config.create_empty_config(random_username)
    
    assert config.config_file.exists()
    assert config._refresh() is not None
    
    # print("\nconfig data:",config._refresh())

def test_save_load_data(config: UserConfig):
    insert_data = ConfigData(
        default_user="test_user",
    )
    config.save_config(data=insert_data)
    
    loaded_data = config.load_config()
    
    assert insert_data == loaded_data
    
    