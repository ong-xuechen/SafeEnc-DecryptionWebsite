from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os

# Generate Key
def generate_key():
    key = get_random_bytes(32)
    with open('encryption_key.key', 'wb') as key_file:
        key_file.write(key)
    return key

# Encrypt File
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        data = file.read()

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file_enc:
        file_enc.write(iv + encrypted_data)

    return encrypted_file_path

# Decrypt File
def decrypt_file(file_path, key):
    with open(file_path, 'rb') as file_enc:
        iv = file_enc.read(16)
        encrypted_data = file_enc.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    decrypted_file_path = file_path[:-4]
    with open(decrypted_file_path, 'wb') as file_dec:
        file_dec.write(decrypted_data)

    return decrypted_file_path
