import tkinter as tk
from tkinter import simpledialog





def gui_password_prompt():
    root = tk.Tk()
    root.withdraw()  
    password = simpledialog.askstring("Мастер-пароль", "Введите мастер пароль:", show='*')
    root.destroy()
    return password