from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, computed_field, field_validator
from typing import Union

from pas_app.schemas.jwt import EncodedToken
from pas_app.schemas.vaults import EncryptedUserVault, VaultData







# ===================================
#               Requests
# ===================================
class Login_RegisterRequest(BaseModel):
    username: str
    password: str

class DownloadRequest(BaseModel):
    backup_id: int

class PullRequestData(BaseModel):
    vault_id: int
    version: int | None
    force: bool

class VaultPushDataRequest(BaseModel):
    id: int | None
    name: str
    salt: str
    entries: int
    encrypted_dek: str
    encrypted_passwords: str
    version: int
    force: bool

class CreateVaultDataRequest(BaseModel):
    name: str
    salt: str
    encrypted_dek: str
    
    @field_validator('name')
    def validate_name(cls, value: str) -> str:
        value = value.strip()
        if not (1 < len(value) < 32):
            raise ValueError("Wrong length of vault name")
        return value

#====================================
class BackupStats(BaseModel):
    backups_count: int
    max_rows: int
    min_rows: int
    avg_rows: int
    backups_for_week: int
 
class BackupData(BaseModel):
    id: int
    name: str
    rows: int
    pinned: bool
    created_at: datetime
    
    @computed_field
    @property
    def created_at_formatted(self) -> str:
        return self.created_at.strftime("%Y-%m-%d %H:%M:%S")
    
class UserData(BaseModel):
    id: int
    username: str
    telegram_id: int | None
    role: str
    is_active: bool
    created_at: datetime

class TypeResponses(StrEnum):
    MESSAGE = "message"
    LOGIN = "login"
    BACKUPS = "backups"
    DOWNLOAD = "download"
    REFRESH = "refresh"
    STATS = "stats"

class PushStatuses(StrEnum):
    PUSHED = 'pushed'
    UP_TO_DATE = 'up_to_date'
    OUTDATED = 'outdated'
    OVERWRITTEN = 'overwritten'
    NOT_FOUND = 'not_found'
    
class PullStatuses(StrEnum):
    PULLED = 'pulled'
    UP_TO_DATE = 'up_to_date'
    LOCAL_AHEAD = 'local_ahead'
    NOT_FOUND = 'not_found'


# ===================================
#               Responses
# ===================================
class MessageResponse(BaseModel):
    # ok: bool
    detail: str
    type: TypeResponses = TypeResponses.MESSAGE

class CreateVaultResponse(MessageResponse):
    vault_id: int

class LoginResponse(MessageResponse):
    bearer_token: EncodedToken
    refresh_token: EncodedToken
    type: TypeResponses = TypeResponses.LOGIN

class RefreshResponse(LoginResponse):
    type: TypeResponses = TypeResponses.REFRESH

class BackupsResponse(MessageResponse):
    backups: list[BackupData]
    type: TypeResponses = TypeResponses.BACKUPS
    
class DownloadResponse(BaseModel):
    vault_data: EncryptedUserVault
    filename: str
    type: TypeResponses = TypeResponses.DOWNLOAD

class BackupStatsResponse(BaseModel):
    ok: bool
    stats: BackupStats
    type: TypeResponses = TypeResponses.STATS
    
class VaultsDataResponse(BaseModel):
    ok: bool
    vaults: list[VaultData]

class VaultDataResponse(BaseModel):
    ok: bool
    vault: VaultData
    
class UnlockVaultResponse(BaseModel):
    ok: bool
    vault_token: str
    detail: str

class UserDataResponse(BaseModel):
    ok: bool
    data: UserData

class PushResponse(MessageResponse):
    status: PushStatuses

class PullResponse(MessageResponse):
    vault_data: EncryptedUserVault | None = None
    status: PullStatuses

class DeleteVaultResponse(MessageResponse):
    vault_id: int
    vault_name: str
    
class RenameVaultResponse(MessageResponse):
    vault_id: int
    old_vault_name: str
    new_vault_name: str

class ApiResponse(BaseModel):
    status_code: int
    content: Union[
        MessageResponse, 
        LoginResponse, 
        BackupsResponse, 
        DownloadResponse, 
        BackupStatsResponse,
        VaultDataResponse,
        VaultsDataResponse,
        UnlockVaultResponse,
        UserDataResponse,
        PushResponse,
        PullResponse,
        DeleteVaultResponse,
        RenameVaultResponse
    ]
    


#====================================