import secrets

import pytest




from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest


def create_random_username() -> str:
    return secrets.token_urlsafe(16)


@pytest.mark.asyncio
async def test_register():
    api = Api()
    
    username = create_random_username()
    user_data = Login_RegisterRequest(
        username=username,
        password="test-password"
    )
    response = await api.register(user_data=user_data)
    
    assert response.status_code == 201


@pytest.mark.asyncio
async def test_double_register():
    api = Api()
    
    username = create_random_username()
    user1 = Login_RegisterRequest(
        username=username,
        password="test-password"
    )
    response = await api.register(user_data=user1)
    
    assert response.status_code == 201
    
    response = await api.register(user_data=user1)
    
    assert response.status_code == 409
    print(response.content)
    










