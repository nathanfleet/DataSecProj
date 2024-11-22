import sqlite3
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from hashlib import sha256
import bcrypt


def encrypt_password(password):
    secret_key = get_random_bytes(32) 
    cipher = AES.new(secret_key, AES.MODE_CBC)
    padding_length = AES.block_size - (len(password) % AES.block_size) 
    padding = chr(padding_length) * padding_length  
    password_padded = password + padding  
    ciphertext = cipher.encrypt(password_padded.encode('utf-8'))  
    
    iv = cipher.iv  
    return ciphertext, iv, secret_key


def decrypt_password(encrypted_password, iv, secret_key):
    try:
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_password).decode('utf-8')

        padding_length = ord(decrypted_data[-1])  
        if padding_length < 1 or padding_length > AES.block_size:
            raise ValueError("Invalid padding length")
        
        return decrypted_data[:-padding_length]
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


def hash_password(password):
    return sha256(password.encode('utf-8')).digest()


def check_password(stored_hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password)
