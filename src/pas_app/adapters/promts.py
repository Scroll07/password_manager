from pathlib import Path
import time
import tkinter as tk
from tkinter import simpledialog
import getpass
from typing import Literal
import typer
from tabulate import tabulate

from pas_app.adapters.console import clear_console
from pas_app.schemas.passwords import ChangePasswordSchema, LoginRegisterInput, Password
from pas_app.schemas.vaults import VaultData, VaultPrintData

# DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def gui_password_prompt():
    root = tk.Tk()
    root.withdraw()
    password = simpledialog.askstring(
        "Мастер-пароль", "Введите мастер пароль:", show="*"
    )
    root.destroy()
    return password


def cli_password_promt():
    while True:
        password = getpass.getpass("Enter password: ").strip()
        if ' ' in password:
            typer.echo("Password must not contain any spaces")
            continue
        return password


def cli_input(text: str, is_secret: bool = False) -> str:
    data = typer.prompt(text=text, hide_input=is_secret)
    return data.strip()


def cli_register_input() -> LoginRegisterInput:
    while True:
        clear_console()
        typer.echo("[Регистрация]")
        login = cli_input("Введите логин")
        if not (4 <= len(login) <= 32):
            typer.echo("Длина Логина должна находиться в диапазоне от 4 до 32")
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



        
            


def choose_current_user(usernames: list[str], current_username: str) -> str:
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
    
def choose_current_vault(data: list[VaultPrintData], current_vault: str) -> str:
    while True:
        clear_console()
        typer.echo(f"Current Vault: {current_vault if current_vault else "Not selected"}")
        typer.echo("Vaults:\n")
        for i, obj in enumerate(data, start=1):
            typer.echo(f'[{i}] - {obj.vault_name} ({obj.filename})')
        choice = typer.prompt("\nChoose vault to set as default").strip()

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(data):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return data[int(choice)-1].filename


def choose_vault(vaults: list[Path], msg: str) -> Path:
    while True:
        clear_console()
        typer.echo("Vault files:\n")
        for i, vault in enumerate(vaults, start=1):
            typer.echo(f'[{i}] - {vault.name}')
        choice = typer.prompt(f"\n{msg}").strip()

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(vaults):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return vaults[int(choice)-1]

def choose_user(usernames: list[str], msg: str) -> str:
    while True:
        clear_console()
        typer.echo("User profiles:\n")
        for i, username in enumerate(usernames, start=1):
            typer.echo(f'[{i}] - {username}')
        choice = typer.prompt(f"\n{msg}").strip()

        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(usernames):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return usernames[int(choice)-1]


def print_passwords(passwords: list[Password], show: bool = False, check: bool = False) -> list[Password]:
    if not passwords:
        typer.echo("No Entries were found")
        raise typer.Exit(code=1)
    rows = []
    if not check:
        headers = ["№", "Service", "Username", "Password", "Note"]
        for i, pas in enumerate(passwords, start=1):
            try:
                match = pas.service
                username = pas.username
                password = pas.password if show else "******"
                note = pas.note
                rows.append([i, match, username, password, note])
            except Exception as e:
                typer.echo(f"Error: {e}")
                raise typer.Exit(code=1)
    else:
        from pas_app.services.password import check_password_strength

        headers = ["№", "Service", "Username", "Password", "Strength"]
        for i, pas in enumerate(passwords, start=1):
            try:
                match = pas.service
                username = pas.username
                password = pas.password if show else "******"
                strength = check_password_strength(password=pas.password)
                rows.append([i, match, username, password, strength])
            except Exception as e:
                typer.echo(f"Error: {e}")
                raise typer.Exit(code=1)

    typer.echo(tabulate(rows, headers=headers, tablefmt="grid"))
    return passwords
 


    

def print_and_choose_password(passwords: list[Password], text: str) -> Password:    
    if not passwords:
        typer.echo("No entries were found")
        raise typer.Exit(code=1)

    while True:
        print_passwords(passwords=passwords)
        choice = typer.prompt(text=text).strip()
        
        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(passwords):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return passwords[int(choice)-1]

def print_vaults(vaults: list[VaultData]) -> list[VaultData]:
    pinned_vaults = sorted([b for b in vaults if b.pinned], key=lambda b: b.created_at, reverse=True)     #ОПТИМИЗИРОВАТЬ
    basic_vaults = sorted([b for b in vaults if not b.pinned], key=lambda b: b.created_at, reverse=True)  #ОПТИМИЗИРОВАТЬ
    headers = ["Id", "Name", "Entries", "Created_at"]

    clear_console()
    if pinned_vaults:
        pinned_data = [[i, b.name, b.entries , b.created_at_formatted] for i, b in enumerate(pinned_vaults, start=1)] 
        typer.echo("Pinned vaults:\n")
        typer.echo(tabulate(pinned_data, headers=headers, floatfmt="grid"))
        
        typer.echo("\n")
    
    if basic_vaults:
        basic_data = [[i, b.name, b.entries , b.created_at_formatted] for i, b in enumerate(basic_vaults, start=len(pinned_vaults) + 1)]
        typer.echo("Vaults:\n")
        typer.echo(tabulate(basic_data, headers=headers, floatfmt="grid"))
    
    result = []
    if pinned_vaults:
        for b in pinned_vaults:
            result.append(b)
    if basic_vaults:
        for b in basic_vaults:
            result.append(b)
    return result
    
    
def print_and_choose_vault(vaults: list[VaultData], text: str) -> VaultData:    
    while True:
        sorted_backups = print_vaults(vaults=vaults)
        typer.echo()
        choice = typer.prompt(text=text).strip()
        
        if not choice.isdigit():
            typer.echo("Input should be digit")
            time.sleep(2)
            continue
        
        if not 1 <= int(choice) <= len(vaults):
            typer.echo("Wrong number input")
            time.sleep(2)
            continue
            
        return sorted_backups[int(choice)-1]
    

def choose_name_for_vault() -> str:
    while True:
        name = typer.prompt("Enter the new vault name").strip()
        if not name:
            continue
        if len(name) > 16:
            typer.echo("Name too long (max 16 characters)")
            continue
        return name
    


def select_master_password() -> str:
    min_length = 4
    max_length = 32
    while True:
        password = typer.prompt("Enter master password", hide_input=True).strip()
        if not password:
            typer.echo("Password cannot be empty")
            continue
        if len(password) < min_length:
            typer.echo(f"Password too short (min {min_length} characters)")
            continue
        if len(password) > max_length:
            typer.echo(f"Password too long (max {max_length} characters)")
            continue
        return password

def select_vault_name() -> str:
    min_length = 4
    max_length = 32
    while True:
        name = typer.prompt("Enter vault name").strip()
        if not name:
            typer.echo("Name cannot be empty")
            continue
        if len(name) < min_length:
            typer.echo(f"Name is too short (min {min_length} characters)")
            continue
        if len(name) > max_length:
            typer.echo(f"Name is too long (max {max_length} characters)")
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
            

action = Literal["download", "change-pin", "rename", "delete", "cancel"]
def choose_action(vault: VaultData) -> action:
    while True:
        clear_console()
        pin_action = "Unpin" if vault.pinned else "Pin"
        text = f"""
        Backup: {vault.name} | entries: {vault.entries} | date: {vault.created_at_formatted} 
        
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
            return "change-pin"
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
        
