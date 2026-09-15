import pytest
from cryptography.fernet import Fernet, InvalidToken
import base64

from pas_app.schemas.jwt import TokenType
from pas_app.schemas.passwords import Password, Passwords
from pas_app.core.crypto import create_random_salt
from pas_app.core.crypto import (
    create_random_salt,
    derive_key,
    create_dek,
    decrypt_dek,
    encrypt_vault_passwords,
    decrypt_vault_passwords,
)
from pas_app.core.crypto import decode_token


def test_create_random_salt__unique_salts():
    salts = []
    for _ in range(10):
        salts.append(create_random_salt())

    assert len(salts) == len(set(salts))
    
def test_create_and_decrypt_dek():
    master_password = 'Password'
    salt = create_random_salt()
    kek = derive_key(master_password=master_password, salt_b64=salt)
    assert type(kek) == bytes
    
    # create_dek funcrion
    # =======================================
    dek = Fernet.generate_key()
    cipher = Fernet(key=kek)
    encrypted_dek = cipher.encrypt(data=dek)
    encrypted_dek_str = base64.b64encode(encrypted_dek).decode("ascii") 
    # ========================================
    decrypted_dek = decrypt_dek(kek=kek, encrypted_dek_str=encrypted_dek_str)
    assert decrypted_dek == dek

def test_encrypt_decrypt_passwords():
    master_password = 'Password'
    salt = create_random_salt()
    kek = derive_key(master_password=master_password, salt_b64=salt)
    assert type(kek) == bytes
    
    # create_dek funcrion
    # =======================================
    dek = Fernet.generate_key()
    cipher = Fernet(key=kek)
    encrypted_dek = cipher.encrypt(data=dek)
    encrypted_dek_str = base64.b64encode(encrypted_dek).decode("ascii") 
    # ========================================
    decrypted_dek = decrypt_dek(kek=kek, encrypted_dek_str=encrypted_dek_str)
    assert decrypted_dek == dek
    
    password = Password(
        service="service",
        username="username",
        password="password",
        note="note"
    )
    passwords = Passwords(passwords=[password])
    encrypted_passwords = encrypt_vault_passwords(passwords=passwords, key=dek)
    decrypted_passwords = decrypt_vault_passwords(encrypted_passwords=encrypted_passwords, key=dek)
    assert passwords == decrypted_passwords





def test_decode_token__ok():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwic2lkIjoyMywiZXhwIjoxNzgyNDIxODUyLCJ0eXBlIjoiYmVhcmVyIn0.eG-Sru7uPuBcl1FJWDAQIiwhl525jHOB9BTi7LeSLik"
    token_data = decode_token(token=token)
    assert token_data.sub
    assert token_data.sid
    assert token_data.exp
    assert token_data.type
    assert token_data.type == TokenType.BEARER
    