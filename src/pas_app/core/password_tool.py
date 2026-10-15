from datetime import datetime
from functools import wraps
import json
from pathlib import Path
from typing import Callable, TypeVar, ParamSpec, cast


from pas_app.services.file_utils import (
    load_data,
    save_data,
)
from pas_app.schemas.passwords import Password, UserVault, Passwords
from pas_app.dependencies import (
    get_keyring_tool,
    get_config,
    get_logger
)
from pas_app.core.settings import IMPORT_DIR, EXPORT_DIR


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

logger = get_logger()


class PasswordTool:
    def __init__(self) -> None:
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        self.username = keyring_data.current_user
        self.vault_name = keyring_data.current_vault
        
        try:
            self._load_data()
        except Exception as e:
            logger.exception(f"Exception while initilization Password tool: {e}")
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
        base = service.strip().lower()
        labels = [p.service for p in self.vault_data.user_passwords if p.service.startswith(base)]
        cantidate = base
        i = 0
        while cantidate in labels:
            cantidate = base + '-' + str(i)
            i += 1
        
        pas_data = Password(
            service=cantidate,
            username=username,
            password=password,
            note=note
        )
        self.vault_data.user_passwords.append(pas_data)
    
    def get_all_passwords(self) -> list[Password]:
        passwords = self.vault_data.user_passwords
        passwords.sort(key=lambda x: x.service)
        return passwords
    
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
        result.sort(key=lambda x: x.service)
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
    def delete(self, service: str, delete_all: bool = False) -> Password | None:
        if delete_all:
            self.vault_data.user_passwords = []
            return
        else: 
            service = service.strip().lower()
            pas = self.get_one_password(service=service)
            if pas is None:
                return None
            self.vault_data.user_passwords.remove(pas)
        
    def find(
        self,
        query: str,
        exact: bool,
    ) -> list[Password]:
        query = query.strip()
        passwords = self.get_all_passwords()
        result = []
        for pas in passwords:
            data = pas.model_dump()
            if exact:
                if query in (data.values()):
                    result.append(pas)
            else:
                if any(query in value for value in data.values()):
                    result.append(pas)
        return result
    
    def export_passwords(
        self,
    ) -> Path:
        if not self.vault_data.user_passwords:
            raise ValueError("No data for export")
        passwords = Passwords(passwords=self.vault_data.user_passwords).model_dump()
        date = datetime.today().strftime("%Y_%m_%d")
        filename = f'{self.username}_{self.vault_name}_{date}.json'
        path = EXPORT_DIR / filename
        with open(path, "w", encoding='utf-8') as f:
            json.dump(passwords, f, indent=4)
        return path

    @vault_transaction
    def import_passwords(
        self,
        passwords: list[Password],
        skip_same_service: bool = False,
        overwrite: bool = False
    ) -> None:
        if skip_same_service and overwrite:
            raise ValueError("incompatible flags")
        if skip_same_service:
            labels = [p.service.lower() for p in self.vault_data.user_passwords]
            for pas in passwords:
                if pas.service.lower() not in labels:
                    self.vault_data.user_passwords.append(pas)
        elif overwrite:
            labels = [p.service.lower() for p in self.vault_data.user_passwords]
            for pas in passwords:
                label = pas.service.lower()
                if label in labels:
                    self.delete(service=label)
                    self.vault_data.user_passwords.append(pas)
        else:
            for pas in passwords:
                self.add(
                    service=pas.service,
                    username=pas.username,
                    password=pas.password,
                    note=pas.note
                )



                    
        
        
        
        
        

# with open(file_path, "r", encoding='utf-8') as f:
#     data = f.read()
# passwords = Passwords.model_validate_json(data).passwords
    
    
        