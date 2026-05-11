from pathlib import Path
import time
import tkinter as tk
from tkinter import simpledialog
import getpass
import typer
from tabulate import tabulate

from pas_app.adapters.console import clear_console
from pas_app.schemas.api import BackupData
from pas_app.schemas.passwords import LoginRegisterInput
from pas_app.config import IMPORT_DIR


def gui_password_prompt():
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring(
        "Мастер-пароль", "Введите мастер пароль:", show="*"
    )
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
        login = cli_input("Введите логин")
        if not (4 <= len(login) <= 16):
            typer.echo("Длина Логина должна находиться в диапазоне от 4 до 16")
            time.sleep(2)
            continue

        password = cli_input("Введите пароль", True)
        confirm_password = cli_input("Повторите пароль", True)

        if password.strip() != confirm_password.strip():
            typer.echo("Пароли должны совпадать")
            time.sleep(2)
            continue

        if not (4 <= len(password) <= 32):
            typer.echo("Длина Пароля должна находиться в диапазоне от 4 до 32")
            time.sleep(2)
            continue

        return LoginRegisterInput(username=login, password=password)


def cli_login_input(username: str | None = None) -> LoginRegisterInput:
    while True:
        clear_console()
        typer.echo("[Вход]")
        if username is None or username == "unauthorized":
            login = cli_input("Введите логин")
        else:
            typer.echo(f"Введите логин: {username}")
            login = username
        if not (4 <= len(login) <= 16):
            typer.echo("Длина Логина должна находиться в диапазоне от 4 до 16")
            time.sleep(2)
            continue

        password = cli_input("Введите пароль", True)

        if not (4 <= len(password) <= 32):
            typer.echo("Длина Пароля должна находиться в диапазоне от 4 до 32")
            time.sleep(2)
            continue

        return LoginRegisterInput(username=login, password=password)


def cli_improt_file_prompt() -> Path:
    files = []
    for file in IMPORT_DIR.glob("*.json"):
        files.append(file)
        
    while True:
        clear_console()
        typer.echo("Files to import:\n")
        for i, file in enumerate(files, start=1):
            typer.echo(f'[{i}] - {file.name}')
        choise = typer.prompt("\nChoose number of file to import")

        if not choise.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choise) <= len(files):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return files[int(choise)-1].absolute()
        
            


def choose_default_user(usernames: list[str]) -> str:
    while True:
        clear_console()
        typer.echo("User profiles:\n")
        for i, username in enumerate(usernames, start=1):
            typer.echo(f'[{i}] - {username}')
        choice = typer.prompt("\nChoose username to set as default")

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(usernames):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return usernames[int(choice)-1]

def choose_backup(backups: list[BackupData]) -> BackupData:
    backups = sorted(backups, key=lambda b: b.created_at, reverse=True)
    headers = ["Id", "Created_at"]
    data = [[i, b.created_at] for i, b in enumerate(backups, start=1)] 
    while True:
        clear_console()
        typer.echo("Backups to download:\n")
        typer.echo(tabulate(data, headers=headers, floatfmt="grid"))

        choice = typer.prompt("Choose backup to download")
        
        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(backups):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return backups[int(choice)-1]








def exit_message_and_clear_console(message: str):
    typer.echo(message)
    time.sleep(2)
    raise typer.Exit(code=0)
