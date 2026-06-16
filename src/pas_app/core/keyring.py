import keyring

from pas_app.schemas.passwords import KeyringValues


#Keyring
SERVICE_NAME = "password_manager"
class KeyringSecrets:
    def __init__(self, service_name: str) -> None:
        self.SERVICE_NAME = service_name

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

def get_keyring_secrets() -> KeyringSecrets:
    return KeyringSecrets(service_name=SERVICE_NAME)