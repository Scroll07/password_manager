from pathlib import Path



BASE_DIR = Path.home() / "pas_data"
EXPORT_DIR = BASE_DIR / "exports"
VAULTS = BASE_DIR / "Vaults"
IMPORT_DIR = BASE_DIR / "imports"
for dir in (BASE_DIR, EXPORT_DIR, VAULTS, IMPORT_DIR):
    dir.mkdir(parents=True, exist_ok=True)


LAST_MATCHES = BASE_DIR / "last_matches.json"
SESSION_FILE = BASE_DIR / "session.json"
CONFIG_FILE = BASE_DIR / "config.json"
