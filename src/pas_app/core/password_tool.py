from functools import wraps
from typing import Callable, TypeVar, ParamSpec, cast

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


P = ParamSpec("P")
R = TypeVar("R")

def vault_transaction(func: Callable[P, R]) -> Callable[P, R]:
    @wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs):
        self = cast("PasswordTool", args[0])
        self._load_data()
        try:
            return func(*args, **kwargs)
        finally:
            self._save_data()
    return wrapper




class PasswordTool:
    def __init__(self) -> None:
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        self.username = keyring_data.current_user
        self.vault_name = keyring_data.current_vault
        
        try:
            self._load_data()
        except Exception as e:
            # add logging
            raise e
    
    
    def _load_data(self) -> None:
        self.vault_data: UserVault = load_data(username=self.username, vault_name=self.vault_name)
    
    def _save_data(self) -> None:
        save_data(
            username=self.username, 
            vault_name=self.vault_name,
            vault_data=self.vault_data
        )

    @vault_transaction    
    def add(
        self,
        service: str,
        username: str,
        password: str,
        note: str = ''
    ) -> None:
        pas_data = Password(
            service=service.strip().lower(),
            username=username,
            password=password,
            note=note
        )
        self.vault_data.user_passwords.append(pas_data)
    
    @vault_transaction
    def get_all_passwords(self) -> list[Password]:
        return self.vault_data.user_passwords
    
    @vault_transaction
    def get_one_password(
        self, 
        service: str,
    ) -> Password | None:
        service = service.strip().lower()
        passwords = self.vault_data.user_passwords
        for p in passwords:
            if p.service == service:
                return p
        return None
    
    @vault_transaction
    def get_passwords_by_service(
        self, 
        service: str
    ) -> list[Password]:
        service = service.strip().lower()
        passwords = self.vault_data.user_passwords
        result = []
        for p in passwords:
            if p.service.startswith(service):
                result.append(p)
        return result

    @vault_transaction
    def edit(
        self,
        service: str,
        username: str | None = None,
        password: str | None = None,
        note: str | None = None,
    ) -> Password | None:
        service = service.strip().lower()
        pas = self.get_one_password(service=service)
        if pas is None:
            return None
        
        pas.username = username if username is not None else pas.username
        pas.password = password if password is not None else pas.password
        pas.note = note if note is not None else pas.note
        return pas
    
    @vault_transaction
    def delete(self, service: str) -> Password | None:
        service = service.strip().lower()
        pas = self.get_one_password(service=service)
        if pas is None:
            return None
        
        self.vault_data.user_passwords.remove(pas)
        
    # @vault_transaction
    # def find(self,)
        
    
    
        