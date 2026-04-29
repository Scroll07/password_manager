from pathlib import Path

from httpx import AsyncClient

from pas_app.config import BASE_URL
from pas_app.schemas.api import Login_RegisterRequest
from pas_app.schemas.api import LoginResponse, MessageResponse, ApiResponse



class Api:
    def __init__(self) -> None:
        self.headers: dict = {}
        self.base_url = BASE_URL
        
    def _update_headers(self, bearer_token: str | None = None) -> None:
        if bearer_token is not None:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        
    async def register(self, user_data:Login_RegisterRequest) -> ApiResponse:
        url = "/register"
        json = user_data.model_dump()
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                json=json,
            )
        
        content = MessageResponse.model_validate(response.json())
        
        return ApiResponse(status_code=response.status_code, content=content)
            
    
    async def login(self, user_data: Login_RegisterRequest) -> ApiResponse:
        url = "/login"
        json = user_data.model_dump()
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                json=json,
            )
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("access_token")
            self._update_headers(bearer_token=token)
        
        content = LoginResponse.model_validate(response.json()) 
            
        return ApiResponse(status_code=response.status_code, content=content)
    
    
    async def upload(self, file_path: Path) -> ApiResponse:
        url = "/backups/upload"
        async with AsyncClient(base_url=self.base_url) as client:
            with open(file_path, "rb") as f:
                response = await client.post(
                    url=url,
                    headers=self.headers,
                    files={"file": f}
                )
        content = MessageResponse.model_validate(response.json())
        
        return ApiResponse(status_code=response.status_code, content=content)
        
        