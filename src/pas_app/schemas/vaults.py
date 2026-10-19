from datetime import datetime
from pydantic import BaseModel, computed_field

from pas_app.schemas.passwords import Password


class CreateVaultData(BaseModel):
    vault_name: str
    vault_master_password: str
    
class VaultData(BaseModel):
    id: int
    name: str
    entries: int
    pinned: bool
    created_at: datetime 

    @computed_field
    @property
    def created_at_formatted(self) -> str:
        return self.created_at.strftime("%Y-%m-%d %H:%M:%S")


class UserVault(BaseModel):
    name: str
    salt: str
    encrypted_dek: str
    user_passwords: list[Password]



class EncryptedUserVault(BaseModel):
    name: str
    salt: str
    encrypted_dek: str
    encrypted_passwords: str