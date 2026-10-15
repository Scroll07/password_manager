from pathlib import Path
import time
import typer
from pydantic import ValidationError

from pas_app.adapters.promts import clear_console
from pas_app.schemas.passwords import EncryptedUserVault, Passwords
from pas_app.core.settings import IMPORT_DIR
from pas_app.dependencies import get_password_tool
from pas_app.services.password import attempt_decrypt_vault
from pas_app.dependencies import get_logger

logger = get_logger()


def get_import_files_paths() -> list[Path]:
    result = []
    for p in IMPORT_DIR.glob("*.json"):
        if p.is_file():
           result.append(p)
    return result
       

def cli_improt_file_prompt(files: list[Path]) -> Path:
    if not files:
        raise FileNotFoundError("No files to import")
        
    while True:
        clear_console()
        typer.echo("Files to import:\n")
        for i, file in enumerate(files, start=1):
            typer.echo(f'[{i}] - {file.name}')
        choice = typer.prompt("\nChoose number of file to import").strip()

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(files):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return files[int(choice)-1].absolute()




def import_data(
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite existing labels"
    ),
    skip_same_service: bool = typer.Option(
        False, "--skip", help="Skip existing labels"
    ),
    will_delete: bool = typer.Option(
        False, "--delete", help="Delete the JSON file after import"
    ),
):
    """
    Import data from a JSON file.

    By default, it imports all data;
    if a name is a duplicate, it adds it with a new service name. 
    Use `--skip` to skip duplicates or `--overwrite` to overwrite them.

    Examples:
        pas import --overwrite

        pas import --skip

        pas import --delete             # Import from JSON and delete file after
    """
    if skip_same_service and overwrite:
        typer.echo("incompatible flags. Use only '--skip'/'--overwrite'")
        return

    files = get_import_files_paths()
    choosed_path = cli_improt_file_prompt(files=files)
    encrypted_vault, passwords = None, None 
    with open(choosed_path, 'r', encoding='utf-8') as f:
        data = f.read()
    try:
        encrypted_vault = EncryptedUserVault.model_validate_json(data)
    except ValidationError:
        try:
            passwords = Passwords.model_validate_json(data)
        except ValidationError as e:
            typer.echo("Incorrect file data structure")
            logger.exception(e)
            raise typer.Exit(code=1)
        
    if encrypted_vault is None and passwords is None:
        typer.echo("Import data is not the vault and is not the passwords")
        return
    elif passwords is not None:
        password_tool = get_password_tool()
        password_tool.import_passwords(
            passwords=passwords.passwords,
            skip_same_service=skip_same_service,
            overwrite=overwrite
        )
        typer.echo("Passowrds were successfully imported")
    elif encrypted_vault is not None:
        if encrypted_vault.encrypted_passwords == '':
            typer.echo("No passwords for import")
            return
        
        username = encrypted_vault.username
        vault_name = choosed_path.name
        i = 0
        while i < 5 and passwords is None:
            passwords = attempt_decrypt_vault(
                username=username,
                vault_name=vault_name, 
                text="Enter master password of import vault"
            )
        if passwords is None:
            typer.echo("Too many attempts")
            return
        
        password_tool = get_password_tool()
        password_tool.import_passwords(
            passwords=passwords,
            skip_same_service=skip_same_service,
            overwrite=overwrite
        )   
        typer.echo("Passowrds were successfully imported from vault")
    
    if will_delete:
        choosed_path.unlink()
        typer.echo("Import file was deleted")
    
    
    
    
    
    
    
