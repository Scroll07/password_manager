from datetime import datetime
from pathlib import Path
from pydantic import BaseModel
import typer

from pas_app.core.crypto import set_keyring_value, get_keyring_value
from pas_app.schemas.passwords import KeyringValues

BASE_DIR = Path.home() / "pas_data"
EXPORT_DIR = BASE_DIR / "exports"
VAULTS = BASE_DIR / "Vaults"
IMPORT_DIR = BASE_DIR / "imports"
for dir in (BASE_DIR, EXPORT_DIR, VAULTS, IMPORT_DIR):
    dir.mkdir(parents=True, exist_ok=True)


LAST_MATCHES = BASE_DIR / "last_matches.json"
SESSION_FILE = BASE_DIR / "session.json"

# BASE_URL = "http://localhost:8000"
BASE_URL = "http://localhost:80"


CONFIG_FILE = BASE_DIR / "config.json"

class ConfigFileData(BaseModel):
    default_user: str = "unauthorized"
    BOT_TOKEN: str = "no token"
    BASE_URL: str = BASE_URL


class KeyringConfig(BaseModel):
    master_password: str = ""
    bearer_token: str = ""                  
    refresh_token: str = ""
    last_action: datetime = datetime.now()


class ConfigData(BaseModel):
    local: ConfigFileData
    keyring: KeyringConfig

class UserConfig:
    def __init__(self, config_file: Path):
        self.config_file = config_file
        self.time_format = "%d-%m-%Y %H:%M:%S"
        # self.config_data = self._refresh()

    def check_exists(self) -> None:
        if not self.config_file.exists():
            typer.echo("Config file does not exist")
            raise typer.Exit(code=1)        
        return None

    def load_config(self) -> ConfigData:
        self.check_exists()
        with open(self.config_file, "r") as f:
            data = f.read()
        file_config = ConfigFileData.model_validate_json(data).model_dump()
        
        last_action_str = get_keyring_value(KeyringValues.LAST_ACTION)
        last_action_datetime = datetime.strptime(last_action_str, self.time_format)
        
        keyring_config = KeyringConfig(
            master_password=get_keyring_value(KeyringValues.MASTER_PASSWORD),
            bearer_token=get_keyring_value(KeyringValues.BEARER_TOKEN),
            refresh_token=get_keyring_value(KeyringValues.REFRESH_TOKEN),
            last_action=last_action_datetime
        ).model_dump()
        
        user_config = ConfigData(local=ConfigFileData(**file_config), keyring=KeyringConfig(**keyring_config))
        return user_config

    def save_config(self, data: ConfigData) -> None: #переделать
        json_data = data.local.model_dump_json(indent=4)
        with open(self.config_file, "w") as f:
            f.write(json_data)
        
        last_action_str = datetime.strftime(datetime.now(), self.time_format)
        set_keyring_value(KeyringValues.MASTER_PASSWORD, data.keyring.master_password)
        set_keyring_value(KeyringValues.BEARER_TOKEN, data.keyring.bearer_token)
        set_keyring_value(KeyringValues.REFRESH_TOKEN, data.keyring.refresh_token)
        set_keyring_value(KeyringValues.LAST_ACTION, last_action_str)
        return None

    def create_empty_config(self, current_user: str) -> None:
        if self.config_file.exists():
            return
        empty_config = ConfigData(
            local=ConfigFileData(default_user=current_user),
            keyring=KeyringConfig()
        )
        self.save_config(empty_config)
        typer.echo("Config file was created")
        return None

    def _refresh(self) -> ConfigData:
        return self.load_config()


config = UserConfig(CONFIG_FILE)
