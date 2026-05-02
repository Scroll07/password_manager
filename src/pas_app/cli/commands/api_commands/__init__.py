import typer

cli_app = typer.Typer()

from pas_app.cli.commands.api_commands.register_cmd import register_command
from pas_app.cli.commands.api_commands.login_cmd import login_command
from pas_app.cli.commands.api_commands.upload_cmd import upload_command

cli_app.command("register")(register_command)
cli_app.command("login")(login_command)
cli_app.command("upload")(upload_command)
