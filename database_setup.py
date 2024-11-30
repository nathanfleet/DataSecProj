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
    secret_key TEXT,
    user_group TEXT
);"""
cursor.execute(sql_command)

# Creating the 'medical_table' table
sql_command = """CREATE TABLE medical_table (
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    gender TEXT,
    age TEXT, 
    weight FLOAT,
    height FLOAT, 
    health_history TEXT,
    doctor_id INTEGER,
    mac TEXT,
    FOREIGN KEY (doctor_id) REFERENCES users(doctor_id)
);"""
cursor.execute(sql_command)

# metadata table to check for query completeness
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='metadata'")
if cursor.fetchone() is None:
    sql_command = """CREATE TABLE metadata (
        total_records INTEGER
    );"""
    cursor.execute(sql_command)
    cursor.execute("SELECT COUNT(*) FROM medical_table")
    current_total_records = cursor.fetchone()[0]
    cursor.execute("INSERT INTO metadata (total_records) VALUES (?)", (current_total_records,))
else:
    cursor.execute("SELECT COUNT(*) FROM medical_table")
    current_total_records = cursor.fetchone()[0]
    cursor.execute("UPDATE metadata SET total_records = ?", (current_total_records,))

# Commit the changes and close the connection
connection.commit()
connection.close()
