import json
import typer

from pas_app.config import EXPORT_DIR
from pas_app.services.file_utils import load_data
from pas_app.config import get_config
from pas_app.adapters.promts import input_filename_for_export

def export_command(
    no_passwords: bool = typer.Option(
        False, "--no-passwords", help="Enable to skip storing passwords in export"
    ),
):
    """
    Export vault data to a JSON file.

    Creates a backup file with all your stored credentials. By default,
    passwords are included; use --no-passwords to exclude them for security.

    Examples:
        pas export my_export.json --no-passwords

        pas export backup.json

        pas export secrets.json
    """
    filename = input_filename_for_export()
    config = get_config()
    data = load_data(config=config)

    if not typer.confirm("Export may expose sensitive data. Continue?"):
        typer.echo("Export was canceled. EXIT")
        return

    export_data = {}
    for pas in data.user_passwords:
        export_pas = {"username": pas.username, "note": pas.note}
        if not no_passwords:
            export_pas["password"] = pas.password
        export_data[pas.service] = export_pas

    filename_path = EXPORT_DIR / filename
    with open(filename_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    typer.echo(f"Data exported to {filename_path} (JSON)")
    raise typer.Exit(code=0)
