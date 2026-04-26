from pydantic import BaseModel


class Login_RegisterRequest(BaseModel):
    username: str
    password: str
    
#===================================
#           Responses
#===================================
class MessageResponse(BaseModel):
    ok: bool
    message: str
    
class LoginResponse(MessageResponse):
    access_token: str
    token_type: str
    
class ApiResponse(BaseModel):
    status_code: int
    content: MessageResponse | Login_RegisterRequest
    
