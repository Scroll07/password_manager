import typer

from pas_app.adapters.promt_gui import gui_password_prompt
from pas_app.config import STORE
from pas_app.core.crypto import decrypt_data, encrypt_data
from pas_app.core.services import get_master_key, save_session


def change_master(
    current_master: str = typer.Argument(..., help='Введите действующий мастер-пароль для смены.')
):
    '''
    Команда для смены мастер-пароля.

    Требует ввода текущего и нового пароля.
    '''
    if not STORE.exists():
        typer.echo('Нет записей. Новый мастер-пароль будет установлен при первом добавлении записи')
        return
    
    typer.echo('Введите новый мастер-пароль в отркывшееся окно.')
    new_master_password = gui_password_prompt()
    if not new_master_password:
        typer.echo('Ввод пароля отменен. ВЫХОД')
        raise typer.Exit()
    
    if new_master_password == current_master:
        typer.echo('Дейвствующий пароль не может совпадать с новым.')
        return

    try:
        current_key = get_master_key(current_master)
        encrypted = STORE.read_bytes()
        if not encrypted: 
            raise ValueError("Хранилище пустое, но файл существует. Проверьте данные.")
        _ = decrypt_data(encrypted, current_key)
    except ValueError:
        typer.echo('Неверный мастер-пароль.')
        raise typer.Exit()
    
    if not typer.confirm('Изменить мастер-пароль? Это действие необратимо!'):
        typer.echo('Смена мастер-пароля отменена.')
        return

    decrypted_data = decrypt_data(encrypted, current_key)
    new_key = get_master_key(new_master_password)
    encrypted_data = encrypt_data(decrypted_data, new_key)
    STORE.write_bytes(encrypted_data)
    typer.echo('Мастер-пароль успешно изменен.')

    save_session(new_key)