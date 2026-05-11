from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel
from typing import Union

from pas_app.schemas.passwords import EncryptedUserVault

class Login_RegisterRequest(BaseModel):
    username: str
    password: str

class DownloadRequest(BaseModel):
    backup_id: int
 
class BackupData(BaseModel):
    id: int
    created_at: datetime
    
class TypeResponses(StrEnum):
    MESSAGE = "message"
    LOGIN = "login"
    BACKUPS = "backups"
    DOWNLOAD = "download"

    
# ===================================
#           Responses
# ===================================
class MessageResponse(BaseModel):
    ok: bool
    message: str
    type: TypeResponses = TypeResponses.MESSAGE

class LoginResponse(MessageResponse):
    access_token: str
    token_type: str
    type: TypeResponses = TypeResponses.LOGIN

class BackupsResponse(MessageResponse):
    backups: list[BackupData]
    type: TypeResponses = TypeResponses.BACKUPS
    
class DownloadResponse(BaseModel):
    vault_data: EncryptedUserVault
    type: TypeResponses = TypeResponses.DOWNLOAD

class ApiResponse(BaseModel):
    status_code: int
    content: Union[MessageResponse, LoginResponse, BackupsResponse, DownloadResponse]
