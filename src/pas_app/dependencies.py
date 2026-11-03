from pas_app.core.keyring import get_keyring_tool
from pas_app.core.logger import get_logger
from pas_app.config import get_config
from pas_app.core.password_tool import PasswordTool

def get_password_tool() -> PasswordTool:
    return PasswordTool()