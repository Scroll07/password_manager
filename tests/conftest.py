import pytest_asyncio
import pytest
import secrets
from keyring.backend import KeyringBackend
import keyring

from pas_app.config import UserConfig
from pas_app.schemas.api import Login_RegisterRequest, LoginResponse
from pas_app.schemas.passwords import UserVault, Password
from pas_app.core.api import Api
from pas_app.services.file_utils import (
    load_data,
    create_vault,
    create_vault_path
)
from pas_app.core.password_tool import PasswordTool
from pas_app.dependencies import get_keyring_tool 
from pas_app.core.keyring import KeyringValues
@pytest.fixture
def api() -> Api:
    return Api()


@pytest.fixture
def config(tmp_path) -> UserConfig:
    test_config = tmp_path / "test_config.json"
    config = UserConfig(test_config)
    return config

@pytest.fixture
def vault_fixture(tmp_path, monkeypatch, test_username, test_vault_name):
    monkeypatch.setattr('pas_app.services.file_utils.VAULTS', tmp_path)
    monkeypatch.setattr("pas_app.services.file_utils.select_new_vault_name", lambda: test_vault_name)
    monkeypatch.setattr("pas_app.services.file_utils.select_master_password", lambda: "admin")
    monkeypatch.setattr("pas_app.services.password.cli_password_promt", lambda: "admin")
    create_vault(username=test_username)
    path = create_vault_path(username=test_username, vault_name=test_vault_name)
    assert path.exists()
    keyring = get_keyring_tool()
    keyring.set_keyring_value(KeyringValues.CURRENT_USER, test_username)
    keyring.set_keyring_value(KeyringValues.CURRENT_VAULT, test_vault_name)


@pytest.fixture
def password_tool(tmp_path, monkeypatch, test_username, test_vault_name, vault_fixture) -> PasswordTool:
    monkeypatch.setattr('pas_app.services.file_utils.VAULTS', tmp_path)
    
    return PasswordTool()


# @pytest.fixture
# def test_vault(tmp_path, monkeypatch, random_username, config) -> UserVault:
#     def mock_cli_input_password() -> str:
#         return "test_password"

#     monkeypatch.setattr(
#         "pas_app.services.password.cli_password_promt", mock_cli_input_password
#     )
#     monkeypatch.setattr("pas_app.services.password.VAULTS", tmp_path)
#     monkeypatch.setattr("pas_app.services.file_utils.VAULTS", tmp_path)

#     create_user_vault(random_username)

#     new_vault = load_data(config=config)

#     return new_vault


# @pytest_asyncio.fixture
# async def create_auth_test_user(
#     random_username,
# ) -> Api:  # Return api to have bearer auth token for new requests
#     api = Api()

#     username = random_username
#     user_data = Login_RegisterRequest(username=username, password="test-password")
#     response = await api.register(user_data=user_data)

#     assert response.status_code == 201

#     response = await api.login(user_data=user_data)

#     assert isinstance(response.content, LoginResponse)
#     assert response.status_code == 200
#     assert response.content.bearer_token
#     assert response.content.refresh_token

#     return api


@pytest.fixture
def passwords() -> list[Password]:
    passwords = []
    for i in range(10):
        passwords.append(
            Password(
                service=str(1),
                username="username",
                password="password",
                note='' if i%2==0 else "note"
            )
        )
    return passwords


@pytest.fixture
def random_username() -> str:
    return secrets.token_urlsafe(16)


@pytest.fixture
def test_username() -> str:
    return "test_user"

@pytest.fixture
def test_vault_name() -> str:
    return "Vault"

class MemoryKeyring(KeyringBackend):
    priority = 1 # type: ignore
    
    def __init__(self):
        self._data = {}
        
    def set_password(self, service: str, username: str, password: str) -> None:
        self._data[(service, username)] = password
        return None
    
    def get_password(self, service: str, username: str) -> str | None:
        return self._data.get((service, username))
    
    def delete_password(self, service: str, username: str) -> None:
        self._data[(service, username)] = ""
        return None
        
@pytest.fixture
def mock_keyring():
    backend = MemoryKeyring()
    old_keyring = keyring.get_keyring()
    keyring.set_keyring(keyring=backend)
    
    yield
    
    keyring.set_keyring(old_keyring)
    
    