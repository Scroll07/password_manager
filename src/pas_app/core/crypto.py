



import json
from cryptography.fernet import Fernet, InvalidToken



def encrypt_data(data: dict, key: bytes) -> bytes:
    json_str = json.dumps(data, ensure_ascii=False)
    bytes_data = json_str.encode('utf-8')
    cipher = Fernet(key)
    encrypted = cipher.encrypt(bytes_data)
    return encrypted

def decrypt_data(encrypted: bytes, key: bytes) -> dict:
    cipher = Fernet(key)
    try:
        decrypted = cipher.decrypt(encrypted)
        json_str = decrypted.decode('utf-8')
        data = json.loads(json_str)
        return data
    except InvalidToken:
        raise ValueError("Неверный ключ или повреждённые данные.")