from functools import wraps
from typing import Callable

from pas_app.services.file_utils import (
    load_data,
    save_data,
)
from pas_app.schemas.passwords import Password, UserVault
from pas_app.dependencies import (
    get_keyring_tool,
    get_config,
    get_logger
)


def vault_transaction(func: Callable):
    @wraps(func)
    def wrapper(self: "PasswordTool", *args, **kwargs):
        self._load_data()
        try:
            return func(args, kwargs)
        finally:
            self._save_data()
    return wrapper




class PasswordTool:
    def __init__(self) -> None:
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        self.username = keyring_data.current_user
        self.vault_name = keyring_data.current_vault
        self._load_data()
        # self.vault_data: UserVault = load_data(username=self.username, vault_name=self.vault_name)
        
    def _load_data(self) -> None:
        self.vault_data: UserVault = load_data(username=self.username, vault_name=self.vault_name)
    
    def _save_data(self) -> None:
        save_data(
            username=self.username, 
            vault_name=self.vault_name,
            vault_data=self.vault_data
        )

    @vault_transaction    
    def add(self, pas_data: Password) -> None:
        self.vault_data.user_passwords.append(pas_data)
    
    @vault_transaction
    def get(self) -> list[Password]:
        return self.vault_data.user_passwords
    
    
        