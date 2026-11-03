import pytest
from datetime import datetime
from pas_app.core.keyring import KeyringData, KeyringValues


def test_set_and_get_keyring_value(keyring_tool):
    keyring_tool.set_keyring_value(KeyringValues.CURRENT_USER, "vlad")
    value = keyring_tool.get_keyring_value(KeyringValues.CURRENT_USER)
    assert value == "vlad"


def test_get_keyring_value_returns_empty_string_when_missing(keyring_tool):
    value = keyring_tool.get_keyring_value(KeyringValues.CURRENT_USER)
    assert value == ""


def test_delete_keyring_value(keyring_tool):
    keyring_tool.set_keyring_value(KeyringValues.CURRENT_USER, "vlad")
    keyring_tool.delete_keyring_value(KeyringValues.CURRENT_USER)
    value = keyring_tool.get_keyring_value(KeyringValues.CURRENT_USER)
    assert value == ""


def test_save_writes_all_fields(keyring_tool):
    data = KeyringData(
        current_user="vlad",
        current_vault="main",
        master_password="secret",
        bearer_token="token123",
        refresh_token="refresh123",
    )
    keyring_tool.save(data)

    assert keyring_tool.get_keyring_value(KeyringValues.CURRENT_USER) == "vlad"
    assert keyring_tool.get_keyring_value(KeyringValues.CURRENT_VAULT) == "main"
    assert keyring_tool.get_keyring_value(KeyringValues.MASTER_PASSWORD) == "secret"
    assert keyring_tool.get_keyring_value(KeyringValues.BEARER_TOKEN) == "token123"
    assert keyring_tool.get_keyring_value(KeyringValues.REFRESH_TOKEN) == "refresh123"
    assert keyring_tool.get_keyring_value(KeyringValues.LAST_ACTION) != ""


def test_save_then_load_roundtrip(keyring_tool):
    data = KeyringData(
        current_user="vlad",
        current_vault="main",
        master_password="secret",
        bearer_token="token123",
        refresh_token="refresh123",
    )
    keyring_tool.save(data)
    loaded = keyring_tool.load()

    assert loaded.current_user == "vlad"
    assert loaded.current_vault == "main"
    assert loaded.master_password == "secret"
    assert loaded.bearer_token == "token123"
    assert loaded.refresh_token == "refresh123"
    assert isinstance(loaded.last_action, datetime)



def test_get_keyring_tool_returns_correct_service_name():
    from pas_app.core.keyring import get_keyring_tool, SERVICE_NAME
    tool = get_keyring_tool()
    assert tool.SERVICE_NAME == SERVICE_NAME