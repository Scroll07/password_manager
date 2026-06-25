# import typer

# from pas_app.services.file_utils import load_data, dump_last_matches
# from pas_app.services.password import print_passwords
# from pas_app.config import get_config


# def check_password_streight_command(
#     service: str = typer.Option("", "--service", "-s", help="Check password of this service, all services by default")
# ):
#     """

#     """
#     config = get_config()
#     data = load_data(config=config)
#     passwords = data.user_passwords

#     if not data or not data.user_passwords:
#         typer.echo("No entries found")
#         return

#     if not service:
#         to_check = 
#     else:
#         passwords = sorted(
#             [p for p in passwords if p.service.lower().startswith(service.lower())],
#             key=lambda p: p.service,
#         )

#     print_passwords(passwords=passwords, show=show)

#     matches = [p.service for p in passwords]
#     dump_last_matches(matches=matches)