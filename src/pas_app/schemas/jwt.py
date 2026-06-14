from datetime import datetime
from enum import StrEnum
from pydantic import BaseModel



class TokenType(StrEnum):
    BEARER = "bearer"
    REFRESH = "refresh"

class TokenData(BaseModel):
    sub: str
    sid: int
    exp: int
    type: TokenType

class EncodedToken(BaseModel):
    token: str
    

class DecodedToken(BaseModel):
    token: TokenData
    token_type: TokenType