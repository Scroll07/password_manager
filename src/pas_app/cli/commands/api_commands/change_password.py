






import typer


from pas_app.adapters.promts import change_password_prompt
from pas_app.core.api import Api
from pas_app.core.logger import get_logger
from pas_app.schemas.api import MessageResponse

logger = get_logger()

async def change_password():
    api = Api()
    data = change_password_prompt()

    logger.info("Change password attempt")
    response = await api.change_password(data=data)
    logger.info(f"Change password response status: {response.status_code}")

    if not isinstance(response.content, MessageResponse):
        logger.error(f"Wrong response from server on change password: {type(response.content)}")
        raise typer.Exit(code=1)

    logger.info("Change password successful")
    typer.echo(response.content.detail)
    
        
        
    
        
    
