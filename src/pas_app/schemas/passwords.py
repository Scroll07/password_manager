from pydantic import BaseModel

class UserVault(BaseModel):
    username: str
    salt: str
    user_passwords: list["Password"]
    
class EncryptedUserVault(BaseModel):
    username: str
    salt: str
    encrypted_passwords: str
    
class Password(BaseModel):
    service: str
    username: str
    password: str
    note: str | None
    
class Passwords(BaseModel):
    passwords: list[Password]


class RegisterInput(BaseModel):
    username: str
    password: str

