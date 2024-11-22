import sqlite3

connection = sqlite3.connect('Masters.db')
cursor = connection.cursor()

# Creating the 'users' table
sql_command = """CREATE TABLE users (
    doctor_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    encrypted_password TEXT,
    iv TEXT,
    hashed_password TEXT,
    secret_key TEXT 
);"""
cursor.execute(sql_command)

# Creating the 'medical_table' table
sql_command = """CREATE TABLE medical_table (
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    gender VARCHAR(1),
    age INT, 
    weight FLOAT,
    height FLOAT, 
    doctor_id INTEGER,
    FOREIGN KEY (doctor_id) REFERENCES users(doctor_id)
);"""
cursor.execute(sql_command)

# Commit the changes and close the connection
connection.commit()
connection.close()
