import time

import pyperclip
import tabulate
import typer

from pas_app.dependencies import get_password_tool
from pas_app.adapters.promts import (
    print_and_choose_password
)


def copy(
    detailed: bool = typer.Option(False, '-d', '--detailed', help="Detailed table of entries.")
    # service: str = typer.Argument(..., help="Service name of password to copy"),
):
    """
    Copy password to clipboard. (List by default)
    """
    password_tool = get_password_tool()
    passwords = password_tool.vault_data.user_passwords
    if not passwords:
        typer.echo("There is no entries to copy anything")
        raise typer.Exit(code=1)
    
    if detailed: 
        choosed_password = print_and_choose_password(passwords=passwords, text="Choose service to copy password")
    else:
        labels = [p.service for p in passwords]
        table = [[i, label] for i, label in enumerate(labels, start=1)]
        while True:
            typer.echo(tabulate.tabulate(table, headers=["№", "Labels"], tablefmt="simple"))
            choice = typer.prompt(text="Choose service to copy password").strip()
            
            if not choice.isdigit():
                typer.echo("Input should be digit")
                time.sleep(2)
                continue
            
            if not 1 <= int(choice) <= len(passwords):
                typer.echo("Wrong number input")
                time.sleep(2)
                continue
                
            choosed_password = passwords[int(choice)-1]

    
    pyperclip.copy(choosed_password.password)
    typer.echo(f"Password for {choosed_password.service} successfully copied to clipboard.")
