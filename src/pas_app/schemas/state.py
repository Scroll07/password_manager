from dataclasses import dataclass
from datetime import datetime

#import api

@dataclass
class State:
    #api: 
    current_user: str | None    #username
    master_password: str | None
    last_action: datetime
    
    
    