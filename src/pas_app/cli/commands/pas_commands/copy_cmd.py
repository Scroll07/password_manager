import json
import pyperclip
import typer

from pas_app.services.file_utils import load_data
from pas_app.config import LAST_MATCHES
from pas_app.config import get_config


def copy(
    idx: int = typer.Argument(..., help="Record number from table (from 1 to N)"),
):
    """
    Copy password to clipboard by number from the last get result.

    First run the 'get' command to display a table with numbers,
    then use 'copy' with the desired number.

    Examples:
        pas get github    # Show table with numbers

        pas copy 1        # Copy password from row #1

        pas copy 3        # Copy password from row #3
    """
    if not LAST_MATCHES.exists():
        typer.echo("File last_matches.json does not exist.")
        return

    try:
        last_matches = json.loads(LAST_MATCHES.read_text("utf-8"))
    except json.JSONDecodeError:
        typer.echo("Error reading last_matches.json.")
        return

    if not last_matches:
        typer.echo("No recent matches found.")
        return

    if idx < 1 or idx > len(last_matches):
        typer.echo(f"Invalid index: {idx}. Available from 1 to {len(last_matches)}.")
        return

    config = get_config()
    data = load_data(config=config)

    match = last_matches[idx - 1]
    passwords = data.user_passwords
    for password in passwords:
        if password.service == match:
            pyperclip.copy(password.password)
            typer.echo(f"Password for {match} successfully copied to clipboard.")
            break
        else:
            typer.echo(f"Password for {match} not found")
