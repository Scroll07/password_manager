from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel, computed_field
from typing import Union

from pas_app.schemas.passwords import EncryptedUserVault
from pas_app.schemas.jwt import EncodedToken
from pas_app.schemas.vaults import VaultData







# ===================================
#               Requests
# ===================================
class Login_RegisterRequest(BaseModel):
    username: str
    password: str

class DownloadRequest(BaseModel):
    backup_id: int

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


# ===================================
#               Responses
# ===================================
class MessageResponse(BaseModel):
    # ok: bool
    detail: str
    type: TypeResponses = TypeResponses.MESSAGE

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
    vault_token: EncodedToken
    detail: str

class UserDataResponse(BaseModel):
    ok: bool
    data: UserData


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
        UserDataResponse
    ]
    


#====================================