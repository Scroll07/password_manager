import typer

from pas_app.config import CONFIG_FILE


def reset_session():
    """Сбросить текущую сессию."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink(missing_ok=True)
    typer.echo("Сессия сброшена.")
