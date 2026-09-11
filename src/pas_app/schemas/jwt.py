from enum import StrEnum
from pydantic import BaseModel

from pas_app.schemas.api import TokenType


class EncodedToken(BaseModel):
    token: str

class TokenData(BaseModel):
    sub: str
    sid: int
    exp: int
    type: TokenType

class DecodedToken(BaseModel):
    token: TokenData
    
