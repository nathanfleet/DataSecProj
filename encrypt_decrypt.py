import os
from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256, pbkdf2_hmac
import hmac
import hashlib
import bcrypt

load_dotenv()

shared_mac_key_hex = os.getenv('SHARED_MAC_KEY')
if shared_mac_key_hex is None:
    raise ValueError("Shared MAC key not found in environment variables.")
SHARED_MAC_KEY = bytes.fromhex(shared_mac_key_hex)

shared_enc_key_hex = os.getenv('SHARED_ENC_KEY')
if shared_enc_key_hex is None:
    raise ValueError("Shared encryption key not found in environment variables.")
SHARED_ENC_KEY = bytes.fromhex(shared_enc_key_hex)

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

def derive_key(password, salt):
    key = pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
    return key

def encrypt_data(data):
    if not isinstance(data, str):
        data = str(data)
    cipher = AES.new(SHARED_ENC_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    iv = cipher.iv
    return iv + ct_bytes

def decrypt_data(enc_data):
    iv = enc_data[:AES.block_size]
    ct = enc_data[AES.block_size:]
    cipher = AES.new(SHARED_ENC_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def compute_mac(data):
    mac = hmac.new(SHARED_MAC_KEY, data.encode('utf-8'), hashlib.sha256).hexdigest()
    return mac

def verify_mac(data, mac):
    computed_mac = hmac.new(SHARED_MAC_KEY, data.encode('utf-8'), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, computed_mac)