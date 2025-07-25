from setuptools import setup

setup(
    name='pas',
    version='0.1.2',
    description='Менеджер паролей на базе Typer.',
    author='Hybrid',
    author_email='vovanikolaev140707@gmail.com',
    py_modules=['pas'],
    install_requires=[
        'typer',
        'pyperclip',
        'tabulate',
        'cryptography',
    ],
    entry_points={
        'console_scripts': [
            'pas = pas:app',
        ],
    },
)








