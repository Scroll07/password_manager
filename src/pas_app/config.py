from pathlib import Path


BASE_DIR = Path.home() / 'pas_data'
BASE_DIR.mkdir(exist_ok=True)
LAST_MATCHES = BASE_DIR / 'last_matches.json'
SESSION_FILE = BASE_DIR / 'session.json'

VAULTS = BASE_DIR / "Vaults"
VAULTS.mkdir(exist_ok=True)
