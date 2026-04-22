from dataclasses import dataclass
from datetime import datetime

from pas_app.core.api import Api

@dataclass
class State:
    api: Api | None
    current_user: str | None    #username
    master_password: str | None
    last_action: datetime
    
    
    