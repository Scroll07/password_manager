from enum import StrEnum
import keyring
from datetime import datetime
from pydantic import BaseModel

class KeyringData(BaseModel):
    current_vault: str = ""
    current_user: str = ""
    master_password: str = ""
    bearer_token: str = ""                  
    refresh_token: str = ""
    vault_token: str = ""
    last_action: datetime = datetime.today()

class KeyringValues(StrEnum):
    CURRENT_USER = "current_user"
    CURRENT_VAULT = 'current_vault'
    MASTER_PASSWORD = "master_password"
    BEARER_TOKEN = "bearer_token"
    REFRESH_TOKEN = "refresh_token"
    VAULT_TOKEN = "vault_token"
    LAST_ACTION = "last_action"



#Keyring
SERVICE_NAME = "password_manager"
class KeyringTool:
    def __init__(self, service_name: str) -> None:
        self.SERVICE_NAME = service_name
        self.time_format = "%d-%m-%Y %H:%M:%S"
        
    def set_keyring_value(self, value_type: KeyringValues, value: str) -> None:
        keyring.set_password(self.SERVICE_NAME, value_type, value)
        return None

    def get_keyring_value(self, value_type: KeyringValues) -> str:
        value = keyring.get_password(self.SERVICE_NAME, value_type)
        if value is None:
            return ""
        return value

    def delete_keyring_value(self, value_type: KeyringValues) -> None:
        keyring.delete_password(self.SERVICE_NAME, value_type)
        return None
    
    def save(self, data: KeyringData) -> None:
        last_action_str = datetime.strftime(datetime.now(), self.time_format)
        self.set_keyring_value(KeyringValues.CURRENT_USER, data.current_user)
        self.set_keyring_value(KeyringValues.CURRENT_VAULT, data.current_vault)
        self.set_keyring_value(KeyringValues.BEARER_TOKEN, data.bearer_token)
        self.set_keyring_value(KeyringValues.MASTER_PASSWORD, data.master_password)
        self.set_keyring_value(KeyringValues.REFRESH_TOKEN, data.refresh_token)
        self.set_keyring_value(KeyringValues.VAULT_TOKEN, data.vault_token)
        self.set_keyring_value(KeyringValues.LAST_ACTION, last_action_str)
        return None
    
    def load(self) -> KeyringData:
        last_action_str = self.get_keyring_value(KeyringValues.LAST_ACTION)
        if last_action_str == '':
            last_action_datetime = datetime(year=1, month=1, day=1)
        else:
            last_action_datetime = datetime.strptime(last_action_str, self.time_format)
        data = KeyringData(
            current_user=self.get_keyring_value(KeyringValues.CURRENT_USER),
            current_vault=self.get_keyring_value(KeyringValues.CURRENT_VAULT),
            master_password=self.get_keyring_value(KeyringValues.MASTER_PASSWORD),
            bearer_token=self.get_keyring_value(KeyringValues.BEARER_TOKEN),
            refresh_token=self.get_keyring_value(KeyringValues.REFRESH_TOKEN),
            vault_token=self.get_keyring_value(KeyringValues.VAULT_TOKEN),
            last_action=last_action_datetime,
        )
        return data

def get_keyring_tool() -> KeyringTool:
    return KeyringTool(service_name=SERVICE_NAME)