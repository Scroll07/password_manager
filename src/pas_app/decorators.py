from functools import wraps
from typing import Callable

import typer

from pas_app.core.api import Api
from pas_app.schemas.api import MessageResponse, RefreshResponse
from pas_app.services.password import check_session   
from pas_app.dependencies import get_keyring_tool

from pas_app.cli.commands.user_commands.set_current_user_cmd import set_current_user


def check_session_dec(func: Callable):
    """
    Check session
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        check_session()
        result = func(*args, **kwargs)
        return result
    return wrapper

def check_token_dec(func: Callable):
    """
    Api check bearer token and try to refresh
    """
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
                    typer.echo(f"Refresh failure, \nMessage: {response.content.detail}\nstatus_code: {response.status_code}")
                    typer.Exit(code=1)                
                raise ValueError("Wrong resposne from api")    
            if response.status_code == 200:
                typer.echo(response.content.detail + "\n")
                result = await func(*args, **kwargs)
                return result
            else:
                typer.echo(f"Refresh failure, \nMessage: {response.content.detail}\nstatus_code: {response.status_code}")
                typer.Exit(code=1)
        else:
            # typer.echo("Tokens are not expired")
            return await func(*args, **kwargs)
                    
    return wrapper   


def check_current_values_dec(func: Callable) -> Callable:
    """
    Check current user is not None and try to set_current_user
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        keyring = get_keyring_tool()
        keyring_data = keyring.load()
        if keyring_data.current_user == '':
            set_current_user()
            typer.echo("Current user does not selected")
            return
        # if keyring_data.current_vault == '':
        #     # add here "set current vault" func
        #     typer.echo("Current vault doesnot selected")
        #     return
        return func(*args, **kwargs)
    return wrapper
