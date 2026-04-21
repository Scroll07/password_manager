import tkinter as tk
from tkinter import simpledialog
import getpass
import typer



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