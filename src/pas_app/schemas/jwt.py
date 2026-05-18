from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel



class TokenType(StrEnum):
    BEARER = "bearer"
    REFRESH = "refresh"

class TokenData(BaseModel):
    user_id: int
    type: TokenType
    exp: datetime

class EncodedToken(BaseModel):
    token: str
    token_type: TokenType
    

class DecodedToken(BaseModel):
    token: TokenData
    token_type: TokenType