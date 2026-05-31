import typer

config_app = typer.Typer(
    help="""
Configuration commands for managing local CLI settings.


Use them to:


- set the default local user;


- view or change the API base URL;


- view or change the bot token;


- reset the current local session.


For more details, run:


  pas config <command> --help
""",
    no_args_is_help=True
)

#imports
from pas_app.cli.commands.config_commands.default_user import set_default_user
from pas_app.cli.commands.config_commands.bot_token import token_cmd
from pas_app.cli.commands.config_commands.url import url_cmd
from pas_app.cli.commands.config_commands.session_cmd import reset_session 

#Maybe decorators



config_app.command("user")(set_default_user)
config_app.command("url")(url_cmd)
config_app.command("token")(token_cmd)
config_app.command("reset-session")(reset_session)






