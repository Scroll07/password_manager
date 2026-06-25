import typer
import json

from pas_app.adapters.promts import cli_password_promt, cli_improt_file_prompt
from pas_app.exceptions import EchoException
from pas_app.schemas.passwords import EncryptedUserVault, Password, UserVault
from pas_app.services.file_utils import delete_file, load_data, save_data
from pas_app.core.crypto import decrypt_vault_passwords, derive_key
from pas_app.config import get_config


def append_into_user_passwords(user_vault: UserVault, passwords: list[Password], overwrite: bool):
    existed_services = {
            p.service: p 
            for p in user_vault.user_passwords
        }

    for pas in passwords:
        if pas.service in existed_services and not overwrite:
            typer.echo(f'SKIPPING - ({pas.service}) already in passwords, use --overwrite to rewrite')
            continue
        elif pas.service in existed_services and overwrite:
            writable = existed_services[pas.service] 
            
            writable.username = pas.username
            writable.password = pas.password
            writable.note = pas.note

            typer.echo(f'({pas.service}) was successfully overwritten')
            continue
        else:
            user_vault.user_passwords.append(pas)
            typer.echo(f'({pas.service}) was successfully added')


def import_data(
    # filename: str = typer.Argument(
    #     ..., help="Name of file to import (e.g., export.json)"
    # ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Overwrite existing labels"
    ),
    will_delete: bool = typer.Option(
        False, "--delete", help="Delete the JSON file after import"
    ),
    is_old_data: bool = typer.Option(
        False, "--old-data", help="Imports data from old version of app, from decrypted data"
    ),
):
    """
    Import data from a JSON file.

    Restores previously exported vault data. Can merge with existing entries
    or overwrite them. Optionally deletes the import file after completion.

    Examples:
        pas import --overwrite

        pas import --delete             # Import from JSON and delete file after
    """
    #Choose import file by cycle
    filename_path = cli_improt_file_prompt()
    
    if not filename_path.exists():
        typer.echo(f"File {filename_path.name} not found.")
        raise typer.Exit(code=1)
    
    with open(filename_path, "r", encoding="utf-8") as f:
        import_data = json.load(f)

    config = get_config()
    current_vault = load_data(config=config)
    if is_old_data:
        try:
            import_passwords = [Password(
                service=key,
                username=p.get("username"),
                password=p.get("password"),
                note=p.get("note")) 
                for key, p in import_data.items()
                ]
        except Exception as e:
            print(e)
            typer.echo("Wrong data for import")
            raise typer.Exit(code=1)
        
        append_into_user_passwords(
            user_vault=current_vault,
            passwords=import_passwords,
            overwrite=overwrite
        )
              
    else:
        try:
            import_data = EncryptedUserVault.model_validate(import_data)
        except Exception:
            typer.echo("Wrong data for import")
            raise typer.Exit(code=1)

        if import_data.username != current_vault.username or import_data.salt != current_vault.salt:
            raise EchoException("Wrong username or salt")
        
        import_password = cli_password_promt()
        
        key = derive_key(import_password, current_vault.salt) 
        decrypted_passwords = decrypt_vault_passwords(encrypted_passwords=import_data.encrypted_passwords, key=key)

        append_into_user_passwords(
            user_vault=current_vault,
            passwords=decrypted_passwords.passwords,
            overwrite=overwrite
        )
            

    save_data(vault_data=current_vault)
    typer.echo(f"Data successfully imported from {filename_path.name}")
    if will_delete:
        delete_file(filename_path)
    else:
        typer.echo(f"File {filename_path.name} was not deleted.")
