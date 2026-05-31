

from pas_app.adapters.promts import choose_default_user
from pas_app.config import get_config
from pas_app.services.file_utils import get_vault_usernames


def set_default_user():
    """
    Set the default local vault user.

    This command lets you choose one of the existing local users and save it
    as the default user for future CLI operations.

    Examples:
        pas config user
    """
    config = get_config()
    usernames = get_vault_usernames()
    username = choose_default_user(usernames=usernames)
    config_data = config._refresh()
    config_data.local.default_user = username
    config.save_config(data=config_data)