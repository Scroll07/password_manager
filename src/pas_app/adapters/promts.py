import time
import tkinter as tk
from tkinter import simpledialog
import getpass
import typer

from pas_app.adapters.console import clear_console
from pas_app.schemas.passwords import LoginRegisterInput


def gui_password_prompt():
    root = tk.Tk()
    root.withdraw()  
    password = simpledialog.askstring("Мастер-пароль", "Введите мастер пароль:", show='*')
    root.destroy()
    return password

def cli_password_promt():
    password = getpass.getpass("Введите пароль: ")
    return password

def cli_input(text: str, is_secret: bool = False) -> str:
    data = typer.prompt(text=text, hide_input=is_secret)
    return data

def cli_register_input() -> LoginRegisterInput:
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
        
        return LoginRegisterInput(username=login, password=password)
    
def cli_login_input() -> LoginRegisterInput:
    while True:
        clear_console()
        typer.echo("[Вход]")
        login = cli_input("Введите логин: ")
        if not (4 <= len(login) <= 16):
            typer.echo("Длина Логина должна находиться в диапазоне от 4 до 16")
            time.sleep(2)
            continue
        
        password = cli_input("Введите пароль: ", True)
                
        if not (4 <= len(password) <= 32):
            typer.echo("Длина Пароля должна находиться в диапазоне от 4 до 32")
            time.sleep(2)
            continue
        
        return LoginRegisterInput(username=login, password=password)


def exit_message_and_clear_console(message: str):
    typer.echo(message)
    time.sleep(2)
    typer.Exit(code=0)