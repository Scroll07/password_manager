
import typer


from pas_app.adapters.promts import choose_backup_delete
from pas_app.core.api import Api
from pas_app.schemas.api import BackupsResponse, MessageResponse

async def delete():
    api = Api()

    response = await api.get_backups()
    if not isinstance(response.content, BackupsResponse):
        if isinstance(response.content, MessageResponse):
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Get backups failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    backups = response.content.backups
    if not backups:
        typer.echo("You have not uploaded backups")
        raise typer.Exit(code=0)
    
    backup = choose_backup_delete(backups=backups)
    
    response = await api.delete(backup_id=backup.id)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Get backups failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    typer.echo(response.content.detail)
        
        
    
        
    
