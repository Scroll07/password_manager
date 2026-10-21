from pathlib import Path
from datetime import timedelta, datetime, timezone
from typing import Callable
from httpx import AsyncClient
from functools import wraps
import re
from pydantic import ValidationError
import typer

from pas_app.dependencies import (
    get_keyring_tool,
    get_config,
    get_logger,
)
from pas_app.schemas.api import (
    CreateVaultDataRequest,
    CreateVaultResponse,
    PullRequestData,
    PullResponse,
    PushResponse,
    UnlockVaultResponse,
    UserDataResponse,
    VaultPushDataRequest,
    VaultsDataResponse,
    VaultDataResponse
)
from pas_app.schemas.api import DownloadRequest, Login_RegisterRequest, RefreshResponse, BackupStatsResponse
from pas_app.schemas.api import LoginResponse, MessageResponse, ApiResponse, BackupsResponse, DownloadResponse
from pas_app.schemas.passwords import ChangePasswordSchema
from pas_app.core.crypto import decode_token
from pas_app.schemas.vaults import EncryptedUserVault


class Api:
    def __init__(self) -> None:
        self.config = get_config()
        self.keyring = get_keyring_tool()
        self.config_data = self.config.load_config()
        self.keyring_data = self.keyring.load()
        self.headers: dict = {}
        self.base_url = f"{self.config_data.BASE_URL}/api"
        
        self.update_headers(
            bearer_token=self.keyring_data.bearer_token, 
            refresh_token=self.keyring_data.refresh_token, 
            save_to_config=False
        )

    def _save_token_to_keyring(
        self, 
        save_to_config: bool = True, 
        bearer_token: str = "", 
        refresh_token: str = "",
        vault_token: str = ""
    ) -> None:
        if not save_to_config:
            return
        self.keyring_data = self.keyring.load()
        if bearer_token:
            self.keyring_data.bearer_token = bearer_token
        if refresh_token:
            self.keyring_data.refresh_token = refresh_token
        if vault_token:
            self.keyring_data.vault_token = vault_token
        
        if bearer_token or refresh_token or vault_token:
            self.keyring.save(data=self.keyring_data)
        
        
    
    def update_headers(
        self, 
        save_to_config: bool = True,
        bearer_token: str = "", 
        refresh_token: str = "", 
        vault_token: str = ""
    ) -> None:
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        if refresh_token:
            self.headers["Refresh"] = refresh_token
        if vault_token:
            self.headers["Vault"] = vault_token
            
        self._save_token_to_keyring(bearer_token=bearer_token, refresh_token=refresh_token, save_to_config=save_to_config)

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
            content = LoginResponse.model_validate(response.json())
            self.update_headers(bearer_token=content.bearer_token.token, refresh_token=content.refresh_token.token)
        else:
            content = MessageResponse.model_validate(response.json())

        return ApiResponse(status_code=response.status_code, content=content)

    async def delete_user(self) -> ApiResponse:
        url = "/users/me"
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.delete(
                url=url,
                headers=self.headers
            )
        content = MessageResponse.model_validate(response.json())
        return ApiResponse(status_code=response.status_code, content=content)

    async def deactivate_user(self) -> ApiResponse:
        url = "/users/me/deactivate"
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers
            )
        content = MessageResponse.model_validate(response.json())
        return ApiResponse(status_code=response.status_code, content=content)

    async def user_me(self) -> ApiResponse:
        url = "/users/me"
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.get(
                url=url,
                headers=self.headers
            )
        data = response.json()
        if response.status_code == 200:
            content = UserDataResponse.model_validate(data)
        else:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    

    async def refresh(self) -> ApiResponse:
        url = "/refresh"
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.get(
                url=url,
                headers=self.headers
            )
        if response.status_code == 200:
            content = RefreshResponse.model_validate(response.json())
            self.update_headers(bearer_token=content.bearer_token.token, refresh_token=content.refresh_token.token)
        else:
            content = MessageResponse.model_validate(response.json())
        
        return ApiResponse(status_code=response.status_code, content=content)  
    
    async def change_password(self, data: ChangePasswordSchema) -> ApiResponse:
        url = "/change-password"
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.patch(
                url=url,
                headers=self.headers,
                json=data.model_dump()
            )
        json = response.json()
        content = MessageResponse(detail=json.get("detail"))
        return ApiResponse(status_code=response.status_code, content=content)              
        
    async def create_vault(
        self,
        payload: CreateVaultDataRequest
    ) -> ApiResponse:
        url = f'/vaults/create'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers,
                json=payload.model_dump()
            )
        data = response.json()
        if response.status_code == 201:
            content = CreateVaultResponse.model_validate(data)
        else:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    
    async def get_vaults(self) -> ApiResponse:
        url = '/vaults'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.get(
                url=url,
                headers=self.headers
            )
        data = response.json()
        if response.status_code == 200:
            content = VaultsDataResponse.model_validate(data)
        else:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    

    async def get_vault(self, vault_id: int) -> ApiResponse:
        url = f'/vaults/{vault_id}'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.get(
                url=url,
                headers=self.headers
            )
        data = response.json()
        if response.status_code == 200:
            content = VaultDataResponse.model_validate(data)
        else:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    
    async def delete_vault(self, vault_id: int) -> ApiResponse:
        url = f'/vaults/{vault_id}'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.delete(
                url=url,
                headers=self.headers
            )
        data = response.json()
        content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    
    async def rename_vault(
        self, 
        vault_id: int,
        new_vault_name: str
    ) -> ApiResponse:
        url = f'/vaults/{vault_id}/rename'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers,
                json=new_vault_name
            )
        data = response.json()
        content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)

    async def change_pin_vault(self, vault_id: int) -> ApiResponse:
        url = f'/vaults/{vault_id}/change-pin'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers
            )
        data = response.json()
        content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
            
    async def download_vault(self, vault_id: int):
        url = f'/vaults/{vault_id}/download'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers
            )
        if response.status_code == 200:
            data = EncryptedUserVault.model_validate_json(response.content)
            header = response.headers.get('Content-Disposition')
            match = None
            if header:
                match = re.search(r'filename="([^"]+\.json)"', header)
            if match:
                filename = match.group(1)
            else:
                date = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") 
                filename = f"vault_{date}.json"
                
            content = DownloadResponse(vault_data=data, filename=filename)
        else:
            content = MessageResponse.model_validate(response.json())
        return ApiResponse(status_code=response.status_code, content=content)
    
    
    async def get_vault_status(self, vault_id: int) -> ApiResponse:
        url = f'/vaults/{vault_id}/status'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers
            )
        data = response.json()
        content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    
    
    async def unlock_vault(self, vault_id: int, vault_master_password: str) -> ApiResponse:
        url = f'/vaults/{vault_id}/unlock'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers,
                json=vault_master_password
            )
        data = response.json()
        if response.status_code == 200:
            content = UnlockVaultResponse.model_validate(data)
            self.update_headers(vault_token=content.vault_token.token)
        else:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
     
    async def push_vault(self, payload: VaultPushDataRequest) -> ApiResponse:
        url = f'/vaults/push'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers,
                json=payload.model_dump()
            )
        data = response.json()
        try:
            content = PushResponse.model_validate(data)
        except ValidationError:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
    
    async def pull_vault(self, payload: PullRequestData) -> ApiResponse:
        url = f'/vaults/pull'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers,
                json=payload.model_dump()
            )
        data = response.json()
        try:
            content = PullResponse.model_validate(data)
        except ValidationError:
            content = MessageResponse.model_validate(data)
        return ApiResponse(status_code=response.status_code, content=content)
        
    
        
    
    async def check_token(self) -> ApiResponse | None:
        token_data = decode_token(token=self.keyring_data.bearer_token)
        if datetime.fromtimestamp(token_data.exp, timezone.utc) - timedelta(minutes=1) < datetime.now(timezone.utc): #12:49 < 12:50
            response = await self.refresh()
            if not isinstance(response.content, RefreshResponse):
                raise ValueError("Wrong resposne from api")
            if response.status_code == 200:
                self.update_headers(
                    bearer_token=response.content.bearer_token.token,
                    refresh_token=response.content.refresh_token.token
                )
            return response
        return None
         