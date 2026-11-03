from datetime import datetime
from pathlib import Path
from pydantic import BaseModel, computed_field, field_validator
from dataclasses import dataclass

from pas_app.schemas.passwords import Password



    
class VaultData(BaseModel):
    id: int
    name: str
    entries: int
    pinned: bool
    version: int
    
    created_at: datetime
    updated_at: datetime

    @computed_field
    @property
    def created_at_formatted(self) -> str:
        return self.created_at.strftime("%Y-%m-%d %H:%M:%S")
        

class UserVault(BaseModel):
    id: int| None
    name: str
    salt: str
    encrypted_dek: str
    user_passwords: list[Password]
    version: int


class EncryptedUserVault(BaseModel):
    id: int | None
    name: str
    salt: str
    encrypted_dek: str
    encrypted_passwords: str
    version: int
    
class VaultPrintData(BaseModel):
    filename: str
    vault_name: str
    version: int
    
@dataclass
class LocalVaultInfo:
    vault: EncryptedUserVault
    path: Path
    
@dataclass
class LocalVaultsData:
    synced: dict[int, LocalVaultInfo]
    unpushed: list[LocalVaultInfo]