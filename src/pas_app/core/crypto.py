


import os
from cryptography.fernet import Fernet
import base64
import hashlib

from pas_app.schemas.passwords import Passwords



# def encrypt_data(data: dict, key: bytes) -> bytes:
#     json_str = json.dumps(data, ensure_ascii=False)
#     bytes_data = json_str.encode('utf-8')
#     cipher = Fernet(key)
#     encrypted = cipher.encrypt(bytes_data)
#     return encrypted

# def decrypt_data(encrypted: bytes, key: bytes) -> dict:
#     cipher = Fernet(key)
#     try:
#         decrypted = cipher.decrypt(encrypted)
#         json_str = decrypted.decode('utf-8')
#         data = json.loads(json_str)
#         return data
#     except InvalidToken:
#         raise ValueError("Неверный ключ или повреждённые данные.")
    
#----NEW----#    
    
def create_random_salt() -> str:
    salt = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    return salt
    
def derive_key(master_password: str, salt_b64: str, iteration: int = 100000) -> bytes:
    salt = base64.urlsafe_b64decode(salt_b64)
    raw_key = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iteration,
        dklen=32
    )
    fernet_key = base64.urlsafe_b64encode(raw_key)
    return fernet_key

    
    
def decrypt_vault_passwords(encrypted_passwords: str, key: bytes) -> Passwords:
    if encrypted_passwords == "":
        return Passwords(passwords=[])
    cipher = Fernet(key)
    decrypted_passwords = cipher.decrypt(encrypted_passwords.encode("ascii"))
    return Passwords.model_validate_json(decrypted_passwords)

def encrypt_vault_passwords(passwords: Passwords, key: bytes) -> str:
    cipher = Fernet(key)
    data = passwords.model_dump_json()
    bytes_to_encrypt = data.encode("utf-8")
    encrypted = cipher.encrypt(bytes_to_encrypt)
    return encrypted.decode("ascii")