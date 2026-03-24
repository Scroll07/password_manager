import typer

from src.config import SESSION_FILE


def reset_session():
    '''Сбросить текущую сессию.'''
    if SESSION_FILE.exists():
        SESSION_FILE.unlink(missing_ok=True)
    typer.echo('Сессия сброшена.')