from pathlib import Path
from pydantic import BaseModel


BASE_DIR = Path.home() / 'pas_data'
BASE_DIR.mkdir(exist_ok=True)
LAST_MATCHES = BASE_DIR / 'last_matches.json'
SESSION_FILE = BASE_DIR / 'session.json'

BASE_URL = "http://localhost"

VAULTS = BASE_DIR / "Vaults"
VAULTS.mkdir(exist_ok=True)

CONFIG_FILE = BASE_DIR / "config.json"


class ConfigData(BaseModel):
    default_user: str
    BASE_URL: str = BASE_URL
    BOT_TOKEN: str

class UserConfig:
    def __init__(self):
        self.config_file = CONFIG_FILE
        self.config_data = self._refresh()

    def check_exists(self) -> None:
        if not self.config_file.exists():
            raise ValueError("Configfile doesnot exist")
        
    def load_config(self) -> ConfigData:
        self.check_exists()
        with open(self.config_file, "r") as f:
            data = f.read()
        user_config = ConfigData.model_validate_json(data)
        return user_config
    
    def save_config(self, data: ConfigData) -> None:
        self.check_exists()
        json = data.model_dump_json()
        with open(self.config_file, "w") as f:
            f.write(json)
        return None
    
    def create_empty_config(self, current_user: str) -> str:
        if self.config_file.exists():
            return "config file already exists"
        
        empty_config = ConfigData(
            default_user=current_user,
            BASE_URL=BASE_URL,
            BOT_TOKEN="No token"
        )
        self.save_config(empty_config)
        return "config file was created"
    
    def _refresh(self) -> ConfigData:
        return self.load_config()