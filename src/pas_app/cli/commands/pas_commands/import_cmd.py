import typer

from pas_app.config import BASE_DIR
from pas_app.adapters.promts import cli_password_promt, cli_improt_file_prompt
from pas_app.schemas.state import State
from pas_app.schemas.passwords import EncryptedUserVault
from pas_app.services.file_utils import delete_file, load_data, save_data
from pas_app.core.crypto import decrypt_vault_passwords, derive_key
from pas_app.config import config



def import_data(
    # filename: str = typer.Argument(
    #     ..., help="Имя файла для импорта (например, export.json)"
    # ),
    overwrite: bool = typer.Option(
        False, "--overwrite", help="Перезаписать существующие метки"
    ),
    will_delete: bool = typer.Option(
        False, "--delete", help="Удалять ли файл json сразу после импорта"
    ),
):
    """
     Импорт данных в store.bin из файла.

    Примеры:

      pas import --overwrite

      pas import --delete             # Импорт из JSON с удалением файла после
    """
    #Choose import file by cicle
    filename_path = cli_improt_file_prompt()
    
    if not filename_path.exists():
        typer.echo(f"Файл {filename_path.name} не найден.")
        raise typer.Exit(code=1)
    
    with open(filename_path, "r", encoding="utf-8") as f:
        import_data = f.read()

    current_vault = load_data(config=config)
    import_data = EncryptedUserVault.model_validate(import_data)


    if import_data.username != current_vault.username or import_data.salt != current_vault.salt:
        raise ValueError("Wrong username or salt")
    
    import_password = cli_password_promt()
    
    key = derive_key(import_password, current_vault.salt) 
    decrypted_passwords = decrypt_vault_passwords(encrypted_passwords=import_data.encrypted_passwords, key=key)


    # if not typer.confirm("Импорт может изменить существующие записи. Продолжить?"):
    #     typer.echo("Импорт отменен. ВЫХОД")
    #     return

    existed_services = {
        p.service: p 
        for p in current_vault.user_passwords
    }

    for pas in decrypted_passwords.passwords:
        if pas.service in existed_services and not overwrite:
            typer.echo(f'SKIPPING - ({pas.service}) already in passwords, use --overwrite to rewrite')
            continue
        elif pas.service in existed_services and overwrite:
            writable = existed_services[pas.service] 
            
            writable.username = pas.username
            writable.password = pas.password
            writable.note = pas.note

            typer.echo(f'({pas.service}) was successfully overwroten')
            continue
        else:
            current_vault.user_passwords.append(pas)
            typer.echo(f'({pas.service}) was successfully added')
            
            
             
        

    save_data(config=config, vault_data=current_vault)
    typer.echo(f"Данные успешно импортированы из {filename_path.name}")
    if will_delete:
        delete_file(filename_path)
    else:
        typer.echo(f"Файл {filename_path.name} не был удален.")
