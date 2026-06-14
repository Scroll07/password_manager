






import typer


from pas_app.adapters.promts import change_password_prompt
from pas_app.core.api import Api
from pas_app.schemas.api import MessageResponse

async def change_password():
    api = Api()
    data = change_password_prompt()
    response = await api.change_password(data=data)
    if not isinstance(response.content, MessageResponse):
            raise typer.Exit(code=1)

    typer.echo(response.content.detail)
    
        
        
    
        
    
