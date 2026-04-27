import pytest

from pas_app.schemas.passwords import UserVault, Password
from pas_app.services.file_utils import load_data





@pytest.mark.sync
def test_load_data():
    