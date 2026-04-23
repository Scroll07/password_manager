from dataclasses import dataclass
from datetime import datetime

from pas_app.core.api import Api
from pas_app.config import UserConfig

@dataclass
class State:
    api: Api | None
    config: UserConfig
    current_user: str | None    #username
    master_password: str | None
    last_action: datetime
    
    
    