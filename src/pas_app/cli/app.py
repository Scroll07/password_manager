import typer

from pas_app.services.password import check_session_dec

from pas_app.cli.commands.pas_commands.add import add_command
from pas_app.cli.commands.pas_commands.list_cmd import list_command
from pas_app.cli.commands.pas_commands.get import get_command
from pas_app.cli.commands.pas_commands.delete import delete_command
from pas_app.cli.commands.pas_commands.find import find_command
from pas_app.cli.commands.pas_commands.edit import edit_command
from pas_app.cli.commands.pas_commands.import_cmd import import_data
from pas_app.cli.commands.pas_commands.export_cmd import export_command
from pas_app.cli.commands.pas_commands.copy_cmd import copy
from pas_app.cli.commands.pas_commands.create_secret_key import create_password_command

from pas_app.cli.commands.api_commands.api_typer import cli_app
from pas_app.cli.commands.config_commands.config_typer import config_app
from pas_app.cli.commands.user_commands.user_typer import user_app

from pas_app.config import get_config


app = typer.Typer(
    help="CLI password manager with a local encrypted vault.",
    no_args_is_help=True,
    context_settings={"max_content_width": 100},
)

#Check session Decorator
add_command = check_session_dec(add_command)
list_command = check_session_dec(list_command)
get_command = check_session_dec(get_command)
copy_command = check_session_dec(copy)
delete_command = check_session_dec(delete_command)
find_command = check_session_dec(find_command)
edit_command = check_session_dec(edit_command)
export_command = check_session_dec(export_command)
import_command = check_session_dec(import_data)




#Base commands
app.command("add")(add_command)
app.command("list")(list_command)
app.command("get")(get_command)
app.command("copy")(copy_command)
app.command("del")(delete_command)
app.command("find")(find_command)
app.command("edit")(edit_command)
app.command("export")(export_command)
app.command("import")(import_command)
app.command("key")(create_password_command)



# APPS
app.add_typer(cli_app, name="api")
app.add_typer(config_app, name="config")
app.add_typer(user_app, name="user")



@app.callback()
def main():
    """Initialize session on startup."""
    try:
        config = get_config()
        config.create_empty_config(current_user="unauthorized")
        # check_session()
    except Exception as e:
        typer.echo(e)
        raise typer.Exit(code=1)
