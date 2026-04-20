from httpx import AsyncClient

from pas_app.config import BASE_URL
from pas_app.schemas.api import Login_RegisterRequest

class Api:
    def __init__(self) -> None:
        self.headers: dict = {}
        self.base_url = BASE_URL
        
    def _update_headers(self, bearer_token: str | None = None) -> None:
        if bearer_token is not None:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        
    async def register(self, user_data:Login_RegisterRequest) -> bool:
        url = "/register"
        json = user_data.model_dump()
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                json=json,
            )
            
        if response.status_code == 201:
            return True
        return False
    
    async def login(self, user_data: Login_RegisterRequest) -> bool:
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
            return True
        return False