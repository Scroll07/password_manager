import pytest


from pas_app.core.api import Api

@pytest.mark.asyncio
async def test_upload_file(tmp_path, random_username, test_vault, create_auth_test_user):
    api: Api = create_auth_test_user
    
    vault_file = tmp_path / f'{random_username}.json'
    
    response = await api.upload(file_path=vault_file)
    
    assert response.status_code == 200