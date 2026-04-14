import secrets
import typer

def create_password_command(
    length: int = typer.Option(16, "-l", "--length", help="password/key length"),
):
    """
    Сгенерировать криптографически стойкий пароль для JWT ключей, паролей БД или API токенов.
    
    Длина по умолчанию 16 символов — достаточно для JWT HS256 ключей.

    
    Примеры:

      pas.py create-password           # Пароль длиной 16 символов

      pas.py create-password -l 32     # Пароль длиной 32 символа

      pas.py create-password --length 64  # Очень длинный ключ (64 символа)
    """
    password = secrets.token_urlsafe(length)
    typer.echo(password)
    
    
    
    
    