from pydantic import BaseModel


class Login_RegisterRequest(BaseModel):
    username: str
    password: str
    
