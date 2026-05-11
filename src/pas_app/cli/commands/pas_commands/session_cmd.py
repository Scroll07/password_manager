import typer

from pas_app.config import CONFIG_FILE
from pas_app.core.crypto import delete_keyring_value
from pas_app.config import KeyringValues


def reset_session():
    """Сбросить текущую сессию."""
    if CONFIG_FILE.exists():
        CONFIG_FILE.unlink(missing_ok=True)

    delete_keyring_value(KeyringValues.MASTER_PASSWORD)
    delete_keyring_value(KeyringValues.BEARER_TOKEN)
    delete_keyring_value(KeyringValues.REFRESH_TOKEN)
    delete_keyring_value(KeyringValues.LAST_ACTION)
    
    typer.echo("Сессия сброшена.")
