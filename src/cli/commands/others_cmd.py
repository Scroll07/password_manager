from pathlib import Path

import typer

from src.config import BASE_DIR

others_typer = typer.Typer()

@others_typer.command()
def get_path():
    '''Показать расположение файла.'''
    typer.echo(f'''
    Данные находяться по пути {BASE_DIR}
    
    Файл pas.py находиться по пути {Path(__file__)}
    ''')