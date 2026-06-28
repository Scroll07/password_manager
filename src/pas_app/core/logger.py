import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from pas_app.config import BASE_DIR

LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "pas_app.log"

class Logger:
    def __init__(self, log_file: Path) -> None:
        self.logger = logging.getLogger("pas_app")
        self.log_file = log_file

        self.init()
    
    def init(self) -> None:
        if self.logger.handlers:
            return
        
        handler = RotatingFileHandler(
            filename=self.log_file,
            maxBytes=1000000,
            backupCount=3,
            encoding="utf-8"
        )
        formatter = logging.Formatter(fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        
        handler.setFormatter(formatter)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(handler)



def get_logger() -> logging.Logger:
    logger = Logger(log_file=LOG_FILE)
    return logger.logger
        