import secrets
import typer

from pas_app.dependencies import get_password_tool



def edit_command(
    service: str = typer.Argument(
        ..., help='Label to edit (e.g., "github-1")'
    ),
    username: str | None = typer.Option(
        None, "-u", "--username", help="New username"
    ),
    password: str | None = typer.Option(None, "-p", "--password", help="New password"),
    note: str | None = typer.Option(None, "--note", help="New note"),
    gen: bool | None = typer.Option(False, "--gen", help="Generate new password"),
    length: int = typer.Option(16, "--length", help="Length of generated password"),
):
    """
    Edit an existing entry.

    Specify only the fields you want to change; others will remain unchanged.
    Shows a preview of changes and requests confirmation before applying.

    Examples:
        pas edit github-1 -u newuser              # Change username only

        pas edit github-1 -p newpass123           # Change password only

        pas edit github-1 --gen --length 24       # Generate new 24-char password

        pas edit github-1 --note "New note"  # Change note only

        pas edit github-1 -u user --gen           # Change username and generate password
    """
    service = service.strip().lower()
    password_tool = get_password_tool()
    pas_to_change = password_tool.get_one_password(service=service)
    if pas_to_change is None:
        typer.echo("No such service in passwords")
        raise typer.Exit()

    if password is not None and gen is not None:
        typer.echo("Cannot use both -p and --gen at the same time. EXIT")
        return
    elif password is None and gen is not None:
        password = secrets.token_urlsafe(length)
    else: 
        password = pas_to_change.password
    
    changes = []
    if username is not None:
        changes.append(f"username: {pas_to_change.username} → {username}  ")
    if password != pas_to_change.password:
        changes.append(
            f"password: {'*' * len(pas_to_change.password)} → {'*' * len(password)}"
        )
    if note is not None:
        changes.append(f"note: {pas_to_change.note} → {note}")

    if not changes:
        typer.echo("No changes to apply.")
        return
    
    typer.echo(f"\nPlanned changes for {service}:")
    for change in changes:
        typer.echo(f"  {change}")

    if not typer.confirm("\nApply changes?"):
        typer.echo("Changes were canceled.")
        return
    
    password_tool.edit(
        service=service,
        username=username,
        password=password,
        note=note
    )   
    
    typer.echo(f"Entry with label {service} was successfully changed.")
