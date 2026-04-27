import pytest




from pas_app.core.api import Api
from pas_app.schemas.api import Login_RegisterRequest





@pytest.mark.asyncio
async def test_succsess_register_login(random_username):
    api = Api()
    username = random_username
    user_data = Login_RegisterRequest(
        username=username,
        password="test-password"
    )
    response = await api.register(user_data=user_data)
    
    assert response.status_code == 201
    
    response = await api.login(user_data=user_data)
    
    assert response.status_code == 200
    assert response.content.access_token is not None # type: ignore
    assert response.content.token_type is not None # type: ignore
    
    print(response.content)
    
    
#test case - brutforce multi login

