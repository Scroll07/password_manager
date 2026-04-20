from pathlib import Path


BASE_DIR = Path.home() / 'pas_data'
BASE_DIR.mkdir(exist_ok=True)
STORE = BASE_DIR / 'store.bin'
LAST_MATCHES = BASE_DIR / 'last_matches.json'
SESSION_FILE = BASE_DIR / 'session.json'
SALT_FILE = BASE_DIR / 'salt_file.bin'

BASE_URL = "http://localhost"