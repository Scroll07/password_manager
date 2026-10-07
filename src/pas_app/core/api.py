from pathlib import Path
from datetime import timedelta, datetime, timezone
from typing import Callable
from httpx import AsyncClient
from functools import wraps

import typer

from pas_app.dependencies import (
    get_keyring_tool,
    get_config,
    get_logger,
)
from pas_app.schemas.api import (
    VaultsDataResponse,
    VaultDataResponse
)
from pas_app.schemas.api import DownloadRequest, Login_RegisterRequest, RefreshResponse, BackupStatsResponse
from pas_app.schemas.api import LoginResponse, MessageResponse, ApiResponse, BackupsResponse, DownloadResponse
from pas_app.schemas.passwords import EncryptedUserVault, ChangePasswordSchema
from pas_app.core.crypto import decode_token
from pas_app.schemas.vaults import CreateVaultData


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

    def _save_token_to_keyring(self, save_to_config: bool = True, bearer_token: str = "", refresh_token: str = "") -> None:
        if not save_to_config:
            return
        self.keyring_data = self.keyring.load()
        if bearer_token:
            self.keyring_data.bearer_token = bearer_token
        if refresh_token:
            self.keyring_data.refresh_token = refresh_token
        
        if bearer_token or refresh_token:
            self.keyring.save(data=self.keyring_data)
        
        
    
    def update_headers(self, bearer_token: str = "", refresh_token: str = "", save_to_config: bool = True) -> None:
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        
        if refresh_token:
            self.headers["Refresh"] = refresh_token
            
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
        vault_data: CreateVaultData
    ) -> ApiResponse:
        url = f'/vaults/create'
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.post(
                url=url,
                headers=self.headers,
                json=vault_data.model_dump()
            )
        data = response.json()
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

        



def check_token_dec(func: Callable):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        api = Api()
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        if not keyring_data.bearer_token or not keyring_data.refresh_token:
            typer.echo("No Tokens\nTry to Login firstly")
            return 
        response = await api.check_token()
        if response is not None:
            if not isinstance(response.content, RefreshResponse):
                if isinstance(response.content, MessageResponse):
                    typer.echo(f"Ошибка при обновлении токенов, \nсообщение: {response.content.detail}\nstatus_code: {response.status_code}")
                    typer.Exit(code=1)                
                raise ValueError("Wrong resposne from api")    
            if response.status_code == 200:
                typer.echo(response.content.detail + "\n")
                result = await func(*args, **kwargs)
                return result
            else:
                typer.echo(f"Ошибка при обновлении токенов, \nсообщение: {response.content.detail}\nstatus_code: {response.status_code}")
                typer.Exit(code=1)
        else:
            # typer.echo("Tokens are not expired")
            return await func(*args, **kwargs)
                    
    return wrapper        