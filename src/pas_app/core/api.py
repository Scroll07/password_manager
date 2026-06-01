from pathlib import Path
from datetime import timedelta, datetime, timezone
from typing import Callable
from httpx import AsyncClient
from functools import wraps

import typer

from pas_app.config import get_config
from pas_app.schemas.api import DownloadRequest, Login_RegisterRequest, RefreshResponse
from pas_app.schemas.api import LoginResponse, MessageResponse, ApiResponse, BackupsResponse, DownloadResponse
from pas_app.schemas.passwords import EncryptedUserVault, ChangePasswordSchema
from pas_app.core.crypto import decode_token


class Api:
    def __init__(self) -> None:
        self.config = get_config()
        self.config_data = self.config._refresh()
        self.headers: dict = {}
        self.base_url = f"{self.config.load_config().local.BASE_URL}/api"
        
        self.update_headers(
            bearer_token=self.config_data.keyring.bearer_token, 
            refresh_token=self.config_data.keyring.refresh_token, 
            save_to_config=False
        )

    def _save_token_to_config(self, save_to_config: bool = True, bearer_token: str = "", refresh_token: str = "") -> None:
        if not save_to_config:
            return
        config_data = self.config._refresh()
        if bearer_token:
            config_data.keyring.bearer_token = bearer_token
        if refresh_token:
            config_data.keyring.refresh_token = refresh_token
        
        if bearer_token or refresh_token:
            self.config.save_config(data=config_data)
        
        
    
    def update_headers(self, bearer_token: str = "", refresh_token: str = "", save_to_config: bool = True) -> None:
        if bearer_token:
            self.headers["Authorization"] = f"Bearer {bearer_token}"
        
        if refresh_token:
            self.headers["Refresh"] = refresh_token
            
        self._save_token_to_config(bearer_token=bearer_token, refresh_token=refresh_token, save_to_config=save_to_config)

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

    async def upload(self, file_path: Path, name: str, rows: int) -> ApiResponse:
        url = "/backups/upload"
        async with AsyncClient(base_url=self.base_url) as client:
            with open(file_path, "rb") as f:
                response = await client.post(
                    url=url, headers=self.headers, files={"file": f}, data={"name": name, "rows": rows}
                )
        if response.status_code == 200:
            content = MessageResponse.model_validate(response.json())
        else:
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
        
    async def rename_backup(self, backup_id: int, new_name: str) -> ApiResponse:
        url = f"/backups/{backup_id}"
        async with AsyncClient(base_url=self.base_url) as client:
            response = await client.patch(
                url=url,
                headers=self.headers,
                json=new_name
            )  
        data = response.json()
        content = MessageResponse(detail=data.get("detail"))
        return ApiResponse(status_code=response.status_code, content=content)
    
    
    
    
    
    
    async def check_token(self) -> ApiResponse | None:
        token_data = decode_token(token=self.config_data.keyring.bearer_token)
        if token_data.exp - timedelta(minutes=1) < datetime.now(timezone.utc): #12:49 < 12:50
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
        config = get_config()
        config_data = config._refresh()
        if not config_data.keyring.bearer_token or not config_data.keyring.refresh_token:
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
            typer.echo("Tokens are not expired")
            return await func(*args, **kwargs)
                    
    return wrapper        