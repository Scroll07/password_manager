from pathlib import Path

from httpx import AsyncClient

from pas_app.config import BASE_URL
from pas_app.schemas.api import DownloadRequest, Login_RegisterRequest
from pas_app.schemas.api import LoginResponse, MessageResponse, ApiResponse, BackupsResponse, DownloadResponse
from pas_app.schemas.passwords import EncryptedUserVault


class Api:
    def __init__(self, bearer_token: str = "") -> None:
        self.headers: dict = {}
        self.base_url = BASE_URL
        self._update_headers(bearer_token=bearer_token)

    def _update_headers(self, bearer_token: str = "") -> None:
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"

    async def register(self, user_data: Login_RegisterRequest) -> ApiResponse:
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

    async def upload(self, file_path: Path, name: str, rows: int) -> ApiResponse:
        url = "/backups/upload"
        async with AsyncClient(base_url=self.base_url) as client:
            with open(file_path, "rb") as f:
                response = await client.post(
                    url=url, headers=self.headers, files={"file": f}, data={"name": name, "rows": rows}
                )
        content = MessageResponse.model_validate(response.json())

        return ApiResponse(status_code=response.status_code, content=content)
    
    async def get_backups(self) -> ApiResponse:
        url = '/backups'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.get(
                url=url,
                headers=self.headers                
            )
        if response.status_code == 200:
            content = BackupsResponse.model_validate(response.json())
        else:
            content = MessageResponse.model_validate(response.json())        

        return ApiResponse(status_code=response.status_code, content=content)
        
    
    async def download(self, backup_id: int) -> ApiResponse:
        url = '/backups/download'
        json = DownloadRequest(backup_id=backup_id).model_dump()
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                json=json,
                headers=self.headers
            )
        if response.status_code == 200:
            vault_data = EncryptedUserVault.model_validate_json(response.content)
            content = DownloadResponse(vault_data=vault_data)
        else:
            content = MessageResponse.model_validate(response.json())
        return ApiResponse(status_code=response.status_code, content=content)
    
    async def delete(self, backup_id: int) -> ApiResponse:
        url = f'/backups/{backup_id}'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.delete(
                url=url,
                headers=self.headers
            )
        content = MessageResponse.model_validate(response.json())
        return ApiResponse(status_code=response.status_code, content=content)
