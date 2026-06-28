from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel
from typing import Union

from pas_app.schemas.passwords import EncryptedUserVault
from pas_app.schemas.jwt import EncodedToken




class TokenType(StrEnum):
    BEARER = "bearer"
    REFRESH = "refresh"

class Token(BaseModel):
    token: str
    token_type: TokenType



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
    type: TypeResponses = TypeResponses.DOWNLOAD

class BackupStatsResponse(BaseModel):
    ok: bool
    stats: BackupStats
    type: TypeResponses = TypeResponses.STATS

class ApiResponse(BaseModel):
    status_code: int
    content: Union[MessageResponse, LoginResponse, BackupsResponse, DownloadResponse, BackupStatsResponse]
    


#====================================