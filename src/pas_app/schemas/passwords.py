from enum import StrEnum

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

class ChangePasswordSchema(BaseModel):
    current_password: str
    new_password: str

class LoginRegisterInput(BaseModel):
    username: str
    password: str


class KeyringValues(StrEnum):
    MASTER_PASSWORD = "master_password"
    BEARER_TOKEN = "bearer_token"
    REFRESH_TOKEN = "refresh_token"
    LAST_ACTION = "last_action"
    