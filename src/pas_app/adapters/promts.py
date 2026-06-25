from pathlib import Path
import time
import tkinter as tk
from tkinter import simpledialog
import getpass
from typing import Literal
import typer
from tabulate import tabulate

from pas_app.adapters.console import clear_console
from pas_app.schemas.api import BackupData
from pas_app.schemas.passwords import ChangePasswordSchema, LoginRegisterInput
from pas_app.config import IMPORT_DIR

DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


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
    return data.strip()


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

        if password != confirm_password:
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
    
    if not files:
        raise FileExistsError("No files to import")
        
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
        
            


def choose_default_user(usernames: list[str], current_username: str) -> str:
    while True:
        clear_console()
        typer.echo(f"Current User: {current_username}")
        typer.echo("User profiles:\n")
        for i, username in enumerate(usernames, start=1):
            typer.echo(f'[{i}] - {username}')
        choice = typer.prompt("\nChoose username to set as default").strip()

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(usernames):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return usernames[int(choice)-1]

def choose_delete_user(usernames: list[str]) -> str:
    while True:
        clear_console()
        typer.echo("User profiles:\n")
        for i, username in enumerate(usernames, start=1):
            typer.echo(f'[{i}] - {username}')
        choice = typer.prompt("\nChoose username to delete").strip()

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(usernames):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return usernames[int(choice)-1]


def print_backups(backups: list[BackupData]) -> list[BackupData]:
    pinned_backups = sorted([b for b in backups if b.pinned], key=lambda b: b.created_at, reverse=True)     #ОПТИМИЗИРОВАТЬ
    basic_backups = sorted([b for b in backups if not b.pinned], key=lambda b: b.created_at, reverse=True)  #ОПТИМИЗИРОВАТЬ
    headers = ["Id", "Name", "Rows", "Created_at"]

    clear_console()
    if pinned_backups:
        pinned_data = [[i, b.name, b.rows , b.created_at.strftime(DATE_FORMAT)] for i, b in enumerate(pinned_backups, start=1)] 
        typer.echo("Pinned Backups:\n")
        typer.echo(tabulate(pinned_data, headers=headers, floatfmt="grid"))
        
        typer.echo("\n")
    
    if basic_backups:
        basic_data = [[i, b.name, b.rows , b.created_at.strftime(DATE_FORMAT)] for i, b in enumerate(basic_backups, start=len(pinned_backups) + 1)]
        typer.echo("Backups:\n")
        typer.echo(tabulate(basic_data, headers=headers, floatfmt="grid"))
    
    result = []
    if pinned_backups:
        for b in pinned_backups:
            result.append(b)
    if basic_backups:
        for b in basic_backups:
            result.append(b)
    return result
    
    
def print_and_choose_backup(backups: list[BackupData], text: str) -> BackupData:    
    while True:
        sorted_backups = print_backups(backups=backups)
        typer.echo()
        choice = typer.prompt(text=text).strip()
        
        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(backups):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return sorted_backups[int(choice)-1]
    

def choose_name_for_backup() -> str:
    while True:
        name = typer.prompt("Input a name for backup").strip()
        if not name:
            continue
        if len(name) > 16:
            typer.echo("too long name - (16 max)")
            continue
        return name

def change_password_prompt() -> ChangePasswordSchema:
    while True:
        clear_console()
        current_password = typer.prompt("Input your current password").strip()
        if not current_password:
            continue
        new_password = typer.prompt("Input new password").strip()
        if not new_password:
            continue
        if not (3 < len(current_password) < 21):
            typer.echo("Current password's length should be: 3 < length < 21")
            time.sleep(2)
            continue
        if not (3 < len(new_password) < 21):
            typer.echo("New password's length should be: 3 < length < 21")
            time.sleep(2)
            continue
        if " " in current_password or " " in new_password:
            typer.echo("Password must not contain spaces")
            time.sleep(2)
            continue
        return ChangePasswordSchema(
            current_password=current_password,
            new_password=new_password
        )
            

action = Literal["download", "pin", "rename", "delete", "cancel"]
def choose_action(backup: BackupData) -> action:
    while True:
        clear_console()
        pin_action = "Unpin" if backup.pinned else "Pin"
        text = f"""
        Backup: {backup.name} | rows: {backup.rows} | date: {backup.created_at.strftime(DATE_FORMAT)} 
        
        1) Download
        2) {pin_action}
        3) Rename (change name)
        4) Delete
        0) Cancel
        
        Input number"""
        choice = typer.prompt(text=text)
        try:
            choice = str(choice).strip()
            if not choice.isdigit():
                typer.echo("Input should be a digit")
                time.sleep(2)
                continue
        except Exception:
            typer.echo("Input should be a digit")
            time.sleep(2)
            continue
        choice = int(choice)
        if choice == 0:
            return "cancel"
        elif choice == 1:
            return "download"
        elif choice == 2:
            return "pin"
        elif choice == 3:
            return "rename"
        elif choice == 4:
            return "delete"
        else:
            continue

def input_new_backup_name() -> str:
    while True:
        clear_console()
        new_name = typer.prompt(text="Input new name for backup").strip()
        if not new_name:
            continue
        if len(new_name) > 20:
            typer.echo("Length of new name must be less than 21")
            time.sleep(2)
            continue
        return new_name


def exit_message_and_clear_console(message: str):
    typer.echo(message)
    time.sleep(2)
    raise typer.Exit(code=0)

def input_filename_for_export() -> str:
    while True:
        clear_console()
        filename = typer.prompt("Filename for export file:").strip()
        if not filename:
            continue
        if len(filename) >= 30:
            typer.echo("Filename is too long")
            time.sleep(2)
        if " " in filename:
            typer.echo("Filename must not contain spaces")
            time.sleep(2)
        if "." in filename:
            typer.echo("Filename must not contain dots")
            time.sleep(2)
        bad_chars = ['<', '>', ':', '"', '/', '\\', '|', '*', '?']
        if any(c in filename for c in bad_chars):
            typer.echo("Filename must not contain bad chars")
            time.sleep(2)
        return f"{filename}.json"
        
