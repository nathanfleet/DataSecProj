import tkinter as tk
from tkinter import messagebox
import sqlite3
from encrypt_decrypt import hash_password, decrypt_password, encrypt_password, encrypt_data, decrypt_data, compute_mac, verify_mac
import base64

conn = sqlite3.connect('Masters.db')
cursor = conn.cursor()

class App:
    conn = sqlite3.connect('Masters.db')
    cursor = conn.cursor()
    def __init__(self):
        self.login_window = tk.Tk()
        self.login_window.title('Login Application')
        

        tk.Label(self.login_window, text='Username').pack()
        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.pack()
        
        tk.Label(self.login_window, text='Password').pack()
        self.password_entry = tk.Entry(self.login_window, show="*") 
        self.password_entry.pack()
        
        self.login_button = tk.Button(self.login_window, text='Login', command=self.login_pg)
        self.login_button.pack()
        
        self.signup_button = tk.Button(self.login_window, text='Sign Up', command=self.sign_up_pg)
        self.signup_button.pack()
        
        self.login_window.mainloop()
    
    def login_pg(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if self.login(username, password): 
            self.homepage()  
        else:
            messagebox.showerror(title='Login Failed', message='Invalid username or password')
            
    def sign_up_pg(self): 
        self.login_window.destroy()
        self.signup_window = tk.Tk()
        self.signup_window.title('Sign Up')

        tk.Label(self.signup_window, text='User Group(H/R)').pack()
        self.user_group_entry = tk.Entry(self.signup_window)
        self.user_group_entry.pack()
        
        tk.Label(self.signup_window, text='Username').pack()
        self.username_entry = tk.Entry(self.signup_window)
        self.username_entry.pack()
        
        tk.Label(self.signup_window, text='Password').pack()
        self.password_entry = tk.Entry(self.signup_window, show="*")
        self.password_entry.pack()
        
        self.signup2_button = tk.Button(self.signup_window, text='Sign Up', command=self.signup_action)
        self.signup2_button.pack()
        
        self.signup_window.mainloop()

    def signup_action(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_group = self.user_group_entry.get().upper()
        if user_group not in ['H', 'R']:
            messagebox.showerror('Error', 'User group must be H or R')
            return
        
        if self.store_user(username, password, user_group): 
            messagebox.showinfo(title='Success', message='User Created')
            self.signup_window.destroy() 
            self.__init__() 
    
    def homepage(self): 
        self.login_window.destroy()
        self.homepage_window = tk.Tk()
        self.homepage_window.title('Homepage Application')

        # Group H gets full access
        if self.user_group == 'H':
            self.add_user_button = tk.Button(self.homepage_window, text='Add A New Patient', command=self.add_new_patient)
            self.add_user_button.pack()
            self.edit_user_button = tk.Button(self.homepage_window, text='Edit An Existing Patient', command=self.begin_edit_window)
            self.edit_user_button.pack()

        self.view_button = tk.Button(self.homepage_window, text='View A Patients Information', command=self.view_action)
        self.view_button.pack()
        self.logout_button = tk.Button(self.homepage_window, text='Logout', command=exit)
        self.logout_button.pack()
        
        self.homepage_window.mainloop()

    def add_new_patient(self):
        self.homepage_window.withdraw()
        self.new_window = tk.Toplevel()
        self.new_window.title("Add a New Patient")

        tk.Label(self.new_window, text="Patient First Name").pack()
        self.first_entry = tk.Entry(self.new_window)
        self.first_entry.pack()

        tk.Label(self.new_window, text="Patient Last Name").pack()
        self.last_entry = tk.Entry(self.new_window)
        self.last_entry.pack()

        tk.Label(self.new_window, text="Patient Gender (M/F)").pack()
        self.gender_entry = tk.Entry(self.new_window)
        self.gender_entry.pack()

        tk.Label(self.new_window, text="Patient Weight (lbs)").pack()
        self.weight_entry = tk.Entry(self.new_window)
        self.weight_entry.pack()

        tk.Label(self.new_window, text="Patient Height (in inches)").pack()
        self.height_entry = tk.Entry(self.new_window)
        self.height_entry.pack()

        tk.Label(self.new_window, text="Patient Age").pack()
        self.age_entry = tk.Entry(self.new_window)
        self.age_entry.pack()

        tk.Label(self.new_window, text="Health History").pack()
        self.health_history_entry = tk.Entry(self.new_window)
        self.health_history_entry.pack()
        
        tk.Button(self.new_window, text="Add Patient", command=self.add_to_database).pack()

    def add_to_database(self):
        try:
            first = self.first_entry.get()
            last = self.last_entry.get()
            gender = self.gender_entry.get()
            age = self.age_entry.get()
            weight = float(self.weight_entry.get())
            height = float(self.height_entry.get())
            health_history = self.health_history_entry.get()

            gender_enc = encrypt_data(gender, self.secret_key)
            age_enc = encrypt_data(age, self.secret_key)
            gender_enc_b64 = base64.b64encode(gender_enc).decode('utf-8')
            age_enc_b64 = base64.b64encode(age_enc).decode('utf-8')

            data_str = f"{first}{last}{gender_enc_b64}{age_enc_b64}{weight}{height}{health_history}{self.doctor_id}"
            mac = compute_mac(data_str, self.secret_key)


            self.cursor.execute(
                "INSERT INTO medical_table (first_name, last_name, gender, age, weight, height, health_history, doctor_id, mac) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (first, last, gender_enc_b64, age_enc_b64, weight, height, health_history, self.doctor_id, mac)
            )
            self.conn.commit()

            messagebox.showinfo("Success", "Patient Added Successfully!")
            self.new_window.destroy()
            self.homepage_window.deiconify()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def begin_edit_window(self):
        if self.user_group != 'H':
            messagebox.showerror("Access Denied", "You do not have permission to edit patient information.")
            return

        self.homepage_window.withdraw()
        self.search_edit_window = tk.Toplevel()
        self.search_edit_window.title("Edit Patient Info")

        tk.Label(self.search_edit_window, text="Patient First Name").pack()
        self.first_edit_entry = tk.Entry(self.search_edit_window)
        self.first_edit_entry.pack()

        tk.Label(self.search_edit_window, text="Patient Last Name").pack()
        self.last_edit_entry = tk.Entry(self.search_edit_window)
        self.last_edit_entry.pack()

        tk.Button(
            self.search_edit_window,
            text="Search",
            command=lambda: self.search_patient(self.first_edit_entry.get(), self.last_edit_entry.get())
        ).pack()

    def search_patient(self, first_name, last_name):
        try:
            self.cursor.execute(
                "SELECT * FROM medical_table WHERE first_name = ? AND last_name = ? AND doctor_id = ?", (first_name, last_name, self.doctor_id)
            )
            result = self.cursor.fetchone()

            if result:
                self.search_edit_window.destroy()
                self.select_to_edit(first_name, last_name, result)
            else:
                messagebox.showerror("Error", "Patient not found!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def select_to_edit(self, first_name, last_name, patient_data):
        self.edit_selection_window = tk.Toplevel()
        self.edit_selection_window.title("Edit Patient Info")

        tk.Button(
            self.edit_selection_window,
            text="Edit Age",
            command=lambda: self.edit_attribute("age", first_name, last_name)
        ).pack()

        tk.Button(
            self.edit_selection_window,
            text="Edit Weight",
            command=lambda: self.edit_attribute("weight", first_name, last_name)
        ).pack()

        tk.Button(
            self.edit_selection_window,
            text="Edit Height",
            command=lambda: self.edit_attribute("height", first_name, last_name)
        ).pack()

    def edit_attribute(self, attribute, first_name, last_name):
        self.edit_selection_window.destroy()
        self.edit_action_window = tk.Toplevel()
        self.edit_action_window.title(f"Edit Patient {attribute.capitalize()}")

        tk.Label(self.edit_action_window, text=f"Enter new {attribute}:").pack()
        new_value_entry = tk.Entry(self.edit_action_window)
        new_value_entry.pack()

        tk.Button(
            self.edit_action_window,
            text="Submit",
            command=lambda: self.update_database(attribute, new_value_entry.get(), first_name, last_name)
        ).pack()

    def update_database(self, attribute, new_value, first_name, last_name):
        try:
            if attribute == "age":
                new_value_str = str(new_value)
                new_value_enc = encrypt_data(new_value_str, self.secret_key)
                new_value_enc_b64 = base64.b64encode(new_value_enc).decode('utf-8')
                query = f"UPDATE medical_table SET {attribute} = ? WHERE first_name = ? AND last_name = ? AND doctor_id = ?"
                self.cursor.execute(query, (new_value_enc_b64, first_name, last_name, self.doctor_id))
            elif attribute == "weight":
                new_value = float(new_value)
                query = f"UPDATE medical_table SET {attribute} = ? WHERE first_name = ? AND last_name = ? AND doctor_id = ?"
                self.cursor.execute(query, (new_value, first_name, last_name, self.doctor_id))
            elif attribute == "height":
                new_value = float(new_value)
                query = f"UPDATE medical_table SET {attribute} = ? WHERE first_name = ? AND last_name = ? AND doctor_id = ?"
                self.cursor.execute(query, (new_value, first_name, last_name, self.doctor_id))

            # Recompute MAC
            self.cursor.execute(
                "SELECT first_name, last_name, gender, age, weight, height, health_history FROM medical_table WHERE first_name = ? AND last_name = ? AND doctor_id = ?",
                (first_name, last_name, self.doctor_id)
            )
            patient_data = self.cursor.fetchone()
            first_name_db, last_name_db, gender_enc_b64, age_enc_b64, weight, height, health_history = patient_data
            data_str = f"{first_name_db}{last_name_db}{gender_enc_b64}{age_enc_b64}{weight}{height}{health_history}{self.doctor_id}"
            mac = compute_mac(data_str, self.secret_key)
            self.cursor.execute(
                "UPDATE medical_table SET mac = ? WHERE first_name = ? AND last_name = ? AND doctor_id = ?",
                (mac, first_name, last_name, self.doctor_id)
            )

            self.conn.commit()

            messagebox.showinfo("Success", f"{attribute.capitalize()} updated successfully!")
            self.return_home(self.edit_action_window)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update {attribute}: {e}")
             
    def view_action(self):
        self.homepage_window.withdraw()
        self.view_action_window = tk.Toplevel()
        self.view_action_window.title("View Patient Info")

        tk.Label(self.view_action_window, text="Patient First Name").pack()
        self.first_view_entry = tk.Entry(self.view_action_window)
        self.first_view_entry.pack()

        tk.Label(self.view_action_window, text="Patient Last Name").pack()
        self.last_view_entry = tk.Entry(self.view_action_window)
        self.last_view_entry.pack()

        tk.Button(
            self.view_action_window,
            text="Search",
            command=lambda: self.view_info(self.first_view_entry.get(), self.last_view_entry.get())
        ).pack(pady=5)

        tk.Button(
            self.view_action_window,
            text="View All Patients",
            command=self.view_all_patients
        ).pack(pady=5)

    def view_all_patients(self):
        try:
            self.cursor.execute(
                "SELECT first_name, last_name, gender, age, weight, height, health_history, mac FROM medical_table"
            )
            results = self.cursor.fetchall()

            if results:
                self.view_action_window.destroy()
                self.view_all_window = tk.Toplevel()
                self.view_all_window.title("All Patients Information")

                # Create a canvas and scrollbar for scrolling
                canvas = tk.Canvas(self.view_all_window)
                scrollbar = tk.Scrollbar(self.view_all_window, orient="vertical", command=canvas.yview)
                scrollable_frame = tk.Frame(canvas)

                scrollable_frame.bind(
                    "<Configure>",
                    lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
                )

                canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
                canvas.configure(yscrollcommand=scrollbar.set)

                canvas.pack(side="left", fill="both", expand=True)
                scrollbar.pack(side="right", fill="y")

                for result in results:
                    first_name_db, last_name_db, gender_enc_b64, age_enc_b64, weight, height, health_history, mac = result

                    # For 'R' users, hide names and encrypted fields
                    if self.user_group == 'R':
                        first_name_db = last_name_db = 'Hidden'
                        gender = age = 'Unavailable'
                    else:
                        # 'H' users can decrypt the fields
                        data_str = f"{first_name_db}{last_name_db}{gender_enc_b64}{age_enc_b64}{weight}{height}{health_history}{self.doctor_id}"
                        if not verify_mac(data_str, mac, self.secret_key):
                            messagebox.showerror("Error", "Data integrity check failed for a record!")
                            continue

                        # Decrypt sensitive data
                        gender_enc = base64.b64decode(gender_enc_b64)
                        age_enc = base64.b64decode(age_enc_b64)
                        gender = decrypt_data(gender_enc, self.secret_key)
                        age = decrypt_data(age_enc, self.secret_key)

                    # Display the patient information
                    patient_info = f"Name: {first_name_db} {last_name_db}\n" \
                                f"Age: {age}\n" \
                                f"Height: {height} in\n" \
                                f"Weight: {weight} lbs\n" \
                                f"Gender: {gender}\n" \
                                f"Health History: {health_history}\n" \
                                "--------------------------------------\n"
                    tk.Label(scrollable_frame, text=patient_info, justify="left", anchor="w").pack(fill="both", expand=True)

                # Add a button to return to the homepage
                tk.Button(self.view_all_window, text="Close", command=lambda: self.return_home(self.view_all_window)).pack(pady=10)
            else:
                messagebox.showinfo("Info", "No patients found.")
                self.view_action_window.destroy()
                self.homepage_window.deiconify()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def view_info(self, first_name, last_name):
        try:
            self.cursor.execute(
                "SELECT first_name, last_name, gender, age, weight, height, health_history, mac FROM medical_table WHERE first_name = ? AND last_name = ?",
                (first_name, last_name)
            )
            result = self.cursor.fetchone()

            if result:
                first_name_db, last_name_db, gender_enc_b64, age_enc_b64, weight, height, health_history, mac = result

                # For 'R' users, hide names and encrypted fields
                if self.user_group == 'R':
                    messagebox.showerror("Access Denied", "You do not have permission to view this patient's detailed information.")
                    self.return_home(self.view_action_window)
                    return
                else:
                    data_str = f"{first_name_db}{last_name_db}{gender_enc_b64}{age_enc_b64}{weight}{height}{health_history}{self.doctor_id}"
                    if not verify_mac(data_str, mac, self.secret_key):
                        messagebox.showerror("Error", "Data integrity check failed!")
                        return

                    # Decrypt sensitive data
                    gender_enc = base64.b64decode(gender_enc_b64)
                    age_enc = base64.b64decode(age_enc_b64)
                    gender = decrypt_data(gender_enc, self.secret_key)
                    age = decrypt_data(age_enc, self.secret_key)

                    self.view_action_window.destroy()
                    self.view_window = tk.Toplevel()
                    self.view_window.title("Patient Information")

                    tk.Label(self.view_window, text=f"Name: {first_name_db} {last_name_db}").pack()
                    tk.Label(self.view_window, text=f"Age: {age}").pack()
                    tk.Label(self.view_window, text=f"Height: {height} in").pack()
                    tk.Label(self.view_window, text=f"Weight: {weight} lbs").pack()
                    tk.Label(self.view_window, text=f"Gender: {gender}").pack()
                    tk.Label(self.view_window, text=f"Health History: {health_history}").pack()

                    tk.Button(self.view_window, text="Close", command=lambda: self.return_home(self.view_window)).pack()
            else:
                messagebox.showerror("Error", "Patient not found!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")


    def return_home(self, window):
        window.destroy()
        self.homepage_window.deiconify()
    
    def login(self, username, password):
        query = "SELECT encrypted_password, iv, hashed_password, secret_key, doctor_id, user_group FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        if result:
            encrypted_password_b64, iv_b64, stored_hashed_password_b64, secret_key_b64, doctor_id, user_group = result
            encrypted_password = base64.b64decode(encrypted_password_b64)
            iv = base64.b64decode(iv_b64)
            secret_key = base64.b64decode(secret_key_b64)
            stored_hashed_password = base64.b64decode(stored_hashed_password_b64)
            decrypted_password = decrypt_password(encrypted_password, iv, secret_key)
            if decrypted_password is None:
                return False
            provided_password_hashed = hash_password(password)
            if stored_hashed_password == provided_password_hashed:
                self.doctor_id = doctor_id
                self.user_group = user_group 
                self.secret_key = secret_key
                return True
            else:
                return False
        else:
            return False
    
    def store_user(self, username, password, user_group):
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if result:
            messagebox.showerror(title='Sign Up Failed', message='Username already exists')
            return False

        if len(password) < 6: 
            messagebox.showerror(title='Password Too Short', message='Password must be at least 6 characters.')
            return False

        encrypted_password, iv, secret_key = encrypt_password(password)  
        hashed_password = hash_password(password)
        encrypted_password_b64 = base64.b64encode(encrypted_password).decode('utf-8')  
        iv_b64 = base64.b64encode(iv).decode('utf-8')  
        secret_key_b64 = base64.b64encode(secret_key).decode('utf-8') 
        hashed_password_b64 = base64.b64encode(hashed_password).decode('utf-8') 

        sql_command = "INSERT INTO users (username, encrypted_password, iv, hashed_password, secret_key, user_group) VALUES (?, ?, ?, ?, ?, ?)"
        values = (username, encrypted_password_b64, iv_b64, hashed_password_b64, secret_key_b64, user_group)
        cursor.execute(sql_command, values)
        conn.commit()
        return True
        
    def logout(self):
        self.homepage_window.destroy()
        conn.close()
        exit()

if __name__ == "__main__":
    App()