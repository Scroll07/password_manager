from datetime import datetime
import pytest_asyncio
import pytest
import secrets

from pas_app.config import UserConfig
from pas_app.schemas.api import Login_RegisterRequest, LoginResponse
from pas_app.schemas.passwords import UserVault
from pas_app.core.api import Api
from pas_app.services.file_utils import load_data
from pas_app.services.password import create_user_vault


@pytest.fixture
def api() -> Api:
    return Api()


@pytest.fixture
def config(tmp_path) -> UserConfig:
    test_config = tmp_path / "test_config.json"
    config = UserConfig(test_config)
    return config


@pytest.fixture
def test_vault(tmp_path, monkeypatch, random_username, config) -> UserVault:
    def mock_cli_input_password() -> str:
        return "test_password"

    monkeypatch.setattr(
        "pas_app.services.password.cli_password_promt", mock_cli_input_password
    )
    monkeypatch.setattr("pas_app.services.password.VAULTS", tmp_path)
    monkeypatch.setattr("pas_app.services.file_utils.VAULTS", tmp_path)

    create_user_vault(random_username)

    new_vault = load_data(config=config)

    return new_vault


@pytest_asyncio.fixture
async def create_auth_test_user(
    random_username,
) -> Api:  # Return api to have bearer auth token for new requests
    api = Api()

    username = random_username
    user_data = Login_RegisterRequest(username=username, password="test-password")
    response = await api.register(user_data=user_data)

    assert response.status_code == 201

    response = await api.login(user_data=user_data)

    assert isinstance(response.content, LoginResponse)
    assert response.status_code == 200
    assert response.content.bearer_token
    assert response.content.refresh_token

    return api


@pytest.fixture
def random_username() -> str:
    return secrets.token_urlsafe(16)


@pytest.fixture
def test_username() -> str:
    return "test_user"


