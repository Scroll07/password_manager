from pathlib import Path
from pydantic import BaseModel

from pas_app.core.settings import CONFIG_FILE



class ConfigData(BaseModel):
    BOT_TOKEN: str = "no token"
    BASE_URL: str = "http://localhost:80"
    COLLECT_STATISTIC: bool = True


class UserConfig:
    def __init__(self, config_file: Path):
        self.config_file = config_file

    def check_exists(self) -> None:
        if not self.config_file.exists():
            raise(FileExistsError(f"{self.config_file} does not exist"))       
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
