import os
from cryptography.fernet import Fernet
import base64
import hashlib
import keyring
import jwt

from pas_app.schemas.jwt import TokenData
from pas_app.schemas.passwords import KeyringValues, Passwords


def create_random_salt() -> str:
    salt = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    return salt


def derive_key(master_password: str, salt_b64: str, iteration: int = 100000) -> bytes:
    salt = base64.urlsafe_b64decode(salt_b64)
    raw_key = hashlib.pbkdf2_hmac(
        "sha256", master_password.encode("utf-8"), salt, iteration, dklen=32
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




    

#JWT
ALGORITM = "HS256"

def decode_token(token: str) -> TokenData:
    decoded = jwt.decode(jwt=token, algorithms=ALGORITM, options={"verify_signature": False})
    return TokenData.model_validate(decoded)

