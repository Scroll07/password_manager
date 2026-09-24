from pas_app.dependencies import get_keyring_tool
from pas_app.adapters.promts import choose_current_user
from pas_app.services.file_utils import get_vault_usernames

def set_current_user():
    keyring = get_keyring_tool()
    keyring_data = keyring.load()
    
    usernames = get_vault_usernames()
    current_user = keyring_data.current_user if keyring_data.current_user else "Not selected"
    selected_user = choose_current_user(usernames=usernames, current_username=current_user)
    
    keyring_data.current_user = selected_user
    keyring.save(data=keyring_data)
    
    