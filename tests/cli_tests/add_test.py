import pytest

from pas_app.cli.commands.pas_commands.add import add_command


@pytest.mark.parametrize(
    "service,username,password,note",
    [
        ["test-service", "test-username", "test-password"]
    ]
)
def test_add_command(
    service: str,
    username: str,
    password: str,
    note: str | None = None
):
    pass
    
    



