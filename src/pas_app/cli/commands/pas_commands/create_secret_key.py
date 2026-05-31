import secrets
import typer


def create_password_command(
    length: int = typer.Option(16, "-l", "--length", help="Password/key length"),
):
    """
    Generate a cryptographically secure password for JWT keys, database passwords, or API tokens.

    Default length is 16 characters, which is sufficient for JWT HS256 keys.
    Increase the length for higher security requirements.

    Examples:
        pas create-password           # 16-character password

        pas create-password -l 32     # 32-character password

        pas create-password --length 64  # Very long key (64 characters)
    """
    password = secrets.token_urlsafe(length)
    typer.echo(password)
