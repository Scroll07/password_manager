
from datetime import datetime

import pytest
import secrets

from pas_app.config import UserConfig
from pas_app.schemas.state import State
from pas_app.core.api import Api
from pas_app.config import BASE_DIR 

@pytest.fixture
def api() -> Api:
    return Api()

@pytest.fixture
def config() -> UserConfig:
    test_config = BASE_DIR / "test_config.json"
    config = UserConfig(test_config)
    return config


@pytest.fixture
def state(api: Api, config: UserConfig) -> State:
    #create test_config with test user
    #create test_account with test master password
    
    
    return State(
        api=api,
        config=config,
        current_user=None,
        master_password=None,
        last_action=datetime.now()
    )



@pytest.fixture
def random_username() -> str:
    return secrets.token_urlsafe(16)



