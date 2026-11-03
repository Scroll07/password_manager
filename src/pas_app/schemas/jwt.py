from enum import StrEnum
from pydantic import BaseModel

class TokenType(StrEnum):
    BEARER = "bearer"
    REFRESH = "refresh"
    VAULT = 'vault'

class Token(BaseModel):
    token: str
    token_type: TokenType
    
class EncodedToken(BaseModel):
    token: str

class TokenData(BaseModel):
    sub: str
    sid: int
    exp: int
    type: TokenType

class DecodedToken(BaseModel):
    token: TokenData
    
