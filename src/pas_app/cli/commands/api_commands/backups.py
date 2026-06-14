import typer


from pas_app.adapters.promts import choose_backup, choose_action, choose_name_for_backup
from pas_app.core.api import Api
from pas_app.schemas.api import BackupData, BackupsResponse, DownloadResponse, MessageResponse
from pas_app.config import VAULTS, UserConfig, get_config


async def delete(backup: BackupData):
    api = Api()

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

async def download(backup: BackupData, config: UserConfig):
    api = Api()
    config_data = config._refresh()
    
    response = await api.download(backup_id=backup.id)
    
    if not isinstance(response.content, DownloadResponse):
        if isinstance(response.content, MessageResponse):
            typer.echo(response.content.detail)
            raise typer.Exit(code=1)
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Download backup failed\nstatus_code: {response.status_code}"
        )
        raise typer.Exit(code=1)

    #save vault file path and write data
    vault_file = VAULTS / f"{config_data.local.default_user}.json"
    if not vault_file.exists():
        typer.echo(f"File {vault_file} does not exist")
        raise typer.Exit(code=1)

    
    data_to_write = response.content.vault_data.model_dump_json()
    
    with open(vault_file, "w", encoding="utf-8") as f:
        f.write(data_to_write)
         
    typer.echo(f"{config_data.local.default_user} vault file was changed")


async def rename(backup: BackupData):
    api = Api()

    new_name = choose_name_for_backup()
    response = await api.rename_backup(backup_id=backup.id, new_name=new_name)
    if not isinstance(response.content, MessageResponse):
        typer.echo("Wrong content from api")
        raise typer.Exit(code=1)
    
    if response.status_code != 200:
        typer.echo(
            f"Rename backup failed\nstatus_code: {response.status_code}, message: {response.content.detail}"
        )
        raise typer.Exit(code=1)
    
    typer.echo(response.content.detail)


async def backups():
    config = get_config()
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
    
    backup = choose_backup(backups=backups, text="Choose backup for action")
    choice = choose_action(backup=backup)
    
    if choice == "cancel":
        typer.echo("Cancel")
        return
    elif choice == "download":
        await download(backup=backup, config=config)
    elif choice == "rename":
        await rename(backup=backup)
    elif choice == "delete":
        await delete(backup=backup)
        
    
    
    
    
  
        
    
