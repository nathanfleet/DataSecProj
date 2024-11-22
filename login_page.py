import tkinter as tk
from tkinter import messagebox
import sqlite3
from turtle import title
from encrypt_decrypt import hash_password, decrypt_password, encrypt_password
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
        
        
        if self.store_user(username, password): 
            messagebox.showinfo(title='Success', message='User Created')
            self.signup_window.destroy() 
            self.__init__() 
    
    def homepage(self): 
        self.login_window.destroy()
        self.homepage_window = tk.Tk()
        self.homepage_window.title('Homepage Application')
        
        self.add_user_button = tk.Button(self.homepage_window, text='Add A New Patient', command=self.add_new_patient)
        self.add_user_button.pack()
        self.edit_user_button = tk.Button(self.homepage_window, text='Edit An Exisiting Patient', command=self.begin_edit_window)
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
        
        tk.Button(self.new_window, text="Add Patient", command=self.add_to_database).pack()

    def add_to_database(self):
        try:
            first = self.first_entry.get()
            last = self.last_entry.get()
            gender = self.gender_entry.get()
            age = int(self.age_entry.get())
            weight = float(self.weight_entry.get())
            height = float(self.height_entry.get())

            self.cursor.execute(
                "INSERT INTO medical_table (first_name, last_name, gender, age, weight, height, doctor_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (first, last, gender, age, weight, height, self.doctor_id)
            )
            self.conn.commit()

            messagebox.showinfo("Success", "Patient Added Successfully!")
            self.new_window.destroy()
            self.homepage_window.deiconify()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def begin_edit_window(self):
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
                "SELECT age, height, weight FROM medical_table WHERE first_name = ? AND last_name = ? AND doctor_id = ?", (first_name, last_name, self.doctor_id)
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
                new_value = int(new_value) 
            elif attribute in ["weight", "height"]:
                new_value = float(new_value)  

            query = f"UPDATE medical_table SET {attribute} = ? WHERE first_name = ? AND last_name = ? AND doctor_id = ?"
            self.cursor.execute(query, (new_value, first_name, last_name, self.doctor_id))
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
        ).pack()

    def view_info(self, first_name, last_name):
        try:
            self.cursor.execute(
                "SELECT age, height, weight, gender FROM medical_table WHERE first_name = ? AND last_name = ? AND doctor_id = ?", (first_name, last_name, self.doctor_id)
            )
            result = self.cursor.fetchone()

            if result:
                age, height, weight,gender = result
                self.view_action_window.destroy()
                self.view_window = tk.Toplevel()
                self.view_window.title("Patient Information")

                tk.Label(self.view_window, text=f"Name: {first_name} {last_name}").pack()
                tk.Label(self.view_window, text=f"Age: {age}").pack()
                tk.Label(self.view_window, text=f"Height: {height} in").pack()
                tk.Label(self.view_window, text=f"Weight: {weight} lbs").pack()
                tk.Label(self.view_window,text = f"Gender: {gender}").pack()

                tk.Button(self.view_window, text="Close", command=lambda: self.return_home(self.view_window)).pack()
            else:
                messagebox.showerror("Error", "Patient not found!")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def return_home(self, window):
        window.destroy()
        self.homepage_window.deiconify()
    def login(self, username, password):
 
        query = "SELECT encrypted_password, iv, hashed_password, secret_key, doctor_id FROM users WHERE username = ?"
        cursor.execute(query, (username,))
    
        result = cursor.fetchone()
    
        if result:
            encrypted_password_b64, iv_b64, stored_hashed_password_b64, secret_key_b64, doctor_id = result


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
                return True
            else:
                return False
        else:
            return False
    
    def store_user(self, username, password):
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

        sql_command = "INSERT INTO users (username, encrypted_password, iv, hashed_password, secret_key) VALUES (?, ?, ?, ?, ?)"
        values = (username, encrypted_password_b64, iv_b64, hashed_password_b64, secret_key_b64)
        cursor.execute(sql_command, values)
        conn.commit()
        return True
        
    def logout(self):
        self.homepage_window.destroy()
        conn.close()
        
    
    
 

if __name__ == "__main__":
    App()
    
