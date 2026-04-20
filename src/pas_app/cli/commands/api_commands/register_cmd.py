import typer
import time


from pas_app.adapters.promts import cli_input
from pas_app.adapters.console import clear_console

async def register_command():
    while True:
        clear_console()
        typer.echo("[Регистрация]")
        login = cli_input("Введите логин: ")
        if not (4 <= len(login) <= 16):
            typer.echo("Длина Логина должна находиться в диапазоне от 4 до 16")
            time.sleep(2)
            continue
        
        password = cli_input("Введите пароль: ", True)
        confirm_password = cli_input("Повторите пароль: ", True)
        
        if password.strip() != confirm_password.strip():
            typer.echo("Пароли должны совпадать")
            time.sleep(2)
            continue
        
        if not (4 <= len(password) <= 32):
            typer.echo("Длина Пароля должна находиться в диапазоне от 4 до 32")
            time.sleep(2)
            continue
         
        
