from datetime import datetime
from pydantic import BaseModel, computed_field


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
       