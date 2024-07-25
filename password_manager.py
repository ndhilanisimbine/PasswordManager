import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
from cryptography.fernet import Fernet
import re

# Generate a key for encryption and decryption
# Save this key securely for later use
key_file = 'secret.key'
try:
    with open(key_file, 'rb') as file:
        key = file.read()
except FileNotFoundError:
    key = Fernet.generate_key()
    with open(key_file, 'wb') as file:
        file.write(key)

cipher_suite = Fernet(key)

# Connect to SQLite database
conn = sqlite3.connect('passwords.db')
c = conn.cursor()

# Create table if it doesn't exist
c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (service TEXT, username TEXT, password TEXT)''')

# Commit changes and close connection
conn.commit()
conn.close()

# Function to add a password
def add_password():
    service = service_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if not service or not username or not password:
        messagebox.showwarning("Input Error", "All fields are required")
        return

    if not validate_password(password):
        messagebox.showwarning("Weak Password", "Password must be at least 8 characters long, contain upper and lower case letters, a number, and a special character.")
        return

    encrypted_password = cipher_suite.encrypt(password.encode()).decode()

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("INSERT INTO passwords (service, username, password) VALUES (?, ?, ?)", 
              (service, username, encrypted_password))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", "Password added successfully")
    service_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

# Function to validate password strength
def validate_password(password):
    if (len(password) >= 8 and re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and re.search(r"[!@#\$%\^&\*]", password)):
        return True
    return False

# Function to view passwords
def view_passwords():
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT * FROM passwords")
    rows = c.fetchall()
    conn.close()

    view_window = tk.Toplevel()
    view_window.title("View Passwords")

    for i, row in enumerate(rows):
        service, username, encrypted_password = row
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        tk.Label(view_window, text=f"Service: {service}").grid(row=i, column=0)
        tk.Label(view_window, text=f"Username: {username}").grid(row=i, column=1)
        tk.Label(view_window, text=f"Password: {decrypted_password}").grid(row=i, column=2)
        tk.Button(view_window, text="Update", command=lambda s=service: update_password(s)).grid(row=i, column=3)
        tk.Button(view_window, text="Delete", command=lambda s=service: delete_password(s)).grid(row=i, column=4)

# Function to update password
def update_password(service):
    new_password = simpledialog.askstring("Update Password", f"Enter new password for {service}:")
    if not new_password:
        return
    if not validate_password(new_password):
        messagebox.showwarning("Weak Password", "Password must be at least 8 characters long, contain upper and lower case letters, a number, and a special character.")
        return

    encrypted_password = cipher_suite.encrypt(new_password.encode()).decode()

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("UPDATE passwords SET password = ? WHERE service = ?", (encrypted_password, service))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", "Password updated successfully")

# Function to delete password
def delete_password(service):
    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE service = ?", (service,))
    conn.commit()
    conn.close()

    messagebox.showinfo("Success", "Password deleted successfully")

# Function to search passwords
def search_password():
    search_service = simpledialog.askstring("Search Password", "Enter service name to search:")
    if not search_service:
        return

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT * FROM passwords WHERE service LIKE ?", ('%' + search_service + '%',))
    rows = c.fetchall()
    conn.close()

    search_window = tk.Toplevel()
    search_window.title("Search Results")

    for i, row in enumerate(rows):
        service, username, encrypted_password = row
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        tk.Label(search_window, text=f"Service: {service}").grid(row=i, column=0)
        tk.Label(search_window, text=f"Username: {username}").grid(row=i, column=1)
        tk.Label(search_window, text=f"Password: {decrypted_password}").grid(row=i, column=2)
        tk.Button(search_window, text="Update", command=lambda s=service: update_password(s)).grid(row=i, column=3)
        tk.Button(search_window, text="Delete", command=lambda s=service: delete_password(s)).grid(row=i, column=4)

# Set up the main application window
root = tk.Tk()
root.title("Password Manager")

tk.Label(root, text="Service").grid(row=0, column=0)
tk.Label(root, text="Username").grid(row=1, column=0)
tk.Label(root, text="Password").grid(row=2, column=0)

service_entry = tk.Entry(root)
username_entry = tk.Entry(root)
password_entry = tk.Entry(root, show="*")

service_entry.grid(row=0, column=1)
username_entry.grid(row=1, column=1)
password_entry.grid(row=2, column=1)

tk.Button(root, text="Add Password", command=add_password).grid(row=3, column=0, columnspan=2)
tk.Button(root, text="View Passwords", command=view_passwords).grid(row=4, column=0, columnspan=2)
tk.Button(root, text="Search Passwords", command=search_password).grid(row=5, column=0, columnspan=2)

root.mainloop()
