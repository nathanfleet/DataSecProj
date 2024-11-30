# script to populate medical table with 100 random records

import sqlite3
import base64
import random
import string
from encrypt_decrypt import (
    hash_password, decrypt_password, encrypt_data, compute_mac
)

def get_doctor_secret_key(username, password):
    conn = sqlite3.connect('Masters.db')
    cursor = conn.cursor()
    
    # Fetch user information
    cursor.execute("SELECT encrypted_password, iv, hashed_password, secret_key, user_group, doctor_id FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    
    if result:
        encrypted_password_b64, iv_b64, stored_hashed_password_b64, secret_key_b64, user_group, doctor_id = result
        encrypted_password = base64.b64decode(encrypted_password_b64)
        iv = base64.b64decode(iv_b64)
        secret_key = base64.b64decode(secret_key_b64)
        stored_hashed_password = base64.b64decode(stored_hashed_password_b64)
        
        # Decrypt the stored encrypted password
        decrypted_password = decrypt_password(encrypted_password, iv, secret_key)
        if decrypted_password is None:
            print("Failed to decrypt stored password.")
            conn.close()
            return None, None, None
        
        # Hash the provided password
        provided_password_hashed = hash_password(password)
        
        # Compare stored hashed password with provided hashed password
        if stored_hashed_password == provided_password_hashed:
            if user_group != 'H':
                print("User must be in group 'H' to add patients.")
                conn.close()
                return None, None, None
            conn.close()
            return doctor_id, secret_key, user_group
        else:
            print("Invalid username or password.")
            conn.close()
            return None, None, None
    else:
        print("User not found.")
        conn.close()
        return None, None, None

def generate_random_patient():
    first_name = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 10)))
    last_name = ''.join(random.choices(string.ascii_letters, k=random.randint(3, 10)))
    gender = random.choice(['M', 'F'])
    age = str(random.randint(1, 100))  
    weight = round(random.uniform(50, 300), 2)  
    height = round(random.uniform(50, 80), 2)  
    health_history = ' '.join(random.choices(string.ascii_letters + ' ', k=random.randint(20, 100)))
    return first_name, last_name, gender, age, weight, height, health_history

def main():
    username = input("Enter doctor username (group 'H'): ")
    password = input("Enter doctor password: ")
    
    doctor_id, secret_key, user_group = get_doctor_secret_key(username, password)
    if doctor_id is None:
        return
    
    conn = sqlite3.connect('Masters.db')
    cursor = conn.cursor()
    
    for i in range(100):
        first_name, last_name, gender, age, weight, height, health_history = generate_random_patient()
        
        # Encrypt gender and age
        gender_enc = encrypt_data(gender)
        age_enc = encrypt_data(age)
        gender_enc_b64 = base64.b64encode(gender_enc).decode('utf-8')
        age_enc_b64 = base64.b64encode(age_enc).decode('utf-8')
        
        # Compute MAC
        data_str = f"{first_name}{last_name}{gender_enc_b64}{age_enc_b64}{weight}{height}{health_history}"
        mac = compute_mac(data_str)
        
        # Insert into database
        cursor.execute(
            "INSERT INTO medical_table (first_name, last_name, gender, age, weight, height, health_history, doctor_id, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (first_name, last_name, gender_enc_b64, age_enc_b64, weight, height, health_history, doctor_id, mac)
        )

        cursor.execute("UPDATE metadata SET total_records = total_records + 1")
        
        print(f"Inserted patient {i+1}: {first_name} {last_name}")
    
    conn.commit()
    conn.close()
    print("Successfully inserted 100 random patient records.")

if __name__ == "__main__":
    main()
