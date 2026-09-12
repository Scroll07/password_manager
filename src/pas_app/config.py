from datetime import datetime
from pathlib import Path
from pydantic import BaseModel
import typer


BASE_DIR = Path.home() / "pas_data"
EXPORT_DIR = BASE_DIR / "exports"
VAULTS = BASE_DIR / "Vaults"
IMPORT_DIR = BASE_DIR / "imports"
for dir in (BASE_DIR, EXPORT_DIR, VAULTS, IMPORT_DIR):
    dir.mkdir(parents=True, exist_ok=True)


LAST_MATCHES = BASE_DIR / "last_matches.json"
SESSION_FILE = BASE_DIR / "session.json"

# BASE_URL = "http://localhost:80"
# BASE_URL = "http://178.72.184.134:80"


CONFIG_FILE = BASE_DIR / "config.json"

class ConfigData(BaseModel):
    BOT_TOKEN: str = "no token"
    BASE_URL: str = "http://localhost:80"
    COLLECT_STATISTIC: bool = True



class UserConfig:
    def __init__(self, config_file: Path):
        self.config_file = config_file

    def check_exists(self) -> None:
        if not self.config_file.exists():
            typer.echo("Config file does not exist")
            raise typer.Exit(code=1)        
        return None

    def load_config(self) -> ConfigData:
        self.check_exists()
        with open(self.config_file, "r") as f:
            data = f.read()
        config_data = ConfigData.model_validate_json(data)
        return config_data

    def save_config(self, data: ConfigData) -> None:
        self.check_exists()
        json_data = data.model_dump_json(indent=4)
        with open(self.config_file, "w") as f:
            f.write(json_data)
        return None

    def create_empty_config(self) -> None:
        if self.config_file.exists():
            return
        empty_config = ConfigData()
        self.save_config(empty_config)
        return None
    
    def reset_config(self) -> None:
        self.check_exists()
        empty_config = ConfigData()
        self.save_config(empty_config)
        return None



def get_config() -> UserConfig:
    return UserConfig(config_file=CONFIG_FILE)
