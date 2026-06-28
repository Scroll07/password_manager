import pytest
from cryptography.fernet import InvalidToken

from pas_app.schemas.api import TokenType
from pas_app.schemas.passwords import Password, Passwords
from pas_app.core.crypto import create_random_salt
from pas_app.core.crypto import derive_key, decrypt_vault_passwords, encrypt_vault_passwords
from pas_app.core.crypto import decode_token


def test_create_random_salt__unique_salts():
    salts = []
    for _ in range(10):
        salts.append(create_random_salt())

    assert len(salts) == len(set(salts))


def test_encrypt_decrypt_passwords__ok(passwords: list[Password]):
    salt = create_random_salt()
    key = derive_key(master_password="master", salt_b64=salt)
    p = Passwords(passwords=passwords)
    
    encrypted = encrypt_vault_passwords(passwords=p, key=key)
    decrypted = decrypt_vault_passwords(encrypted_passwords=encrypted, key=key)
    
    assert p == decrypted
    
def test_encrypt_decrypt_passwords__wrong_key__exception(passwords: list[Password]):
    with pytest.raises(InvalidToken):
        salt = create_random_salt()
        key = derive_key(master_password="master", salt_b64=salt)
        wrong_key = derive_key(master_password="wrong", salt_b64=salt)
        p = Passwords(passwords=passwords)
        
        encrypted = encrypt_vault_passwords(passwords=p, key=key)
        decrypted = decrypt_vault_passwords(encrypted_passwords=encrypted, key=wrong_key)

def test_decode_token__ok():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIyIiwic2lkIjoyMywiZXhwIjoxNzgyNDIxODUyLCJ0eXBlIjoiYmVhcmVyIn0.eG-Sru7uPuBcl1FJWDAQIiwhl525jHOB9BTi7LeSLik"
    token_data = decode_token(token=token)
    assert token_data.sub
    assert token_data.sid
    assert token_data.exp
    assert token_data.type
    assert token_data.type == TokenType.BEARER
    