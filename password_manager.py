import tkinter as tk
from tkinter import messagebox, simpledialog
import sqlite3
import hashlib
import re
from cryptography.fernet import Fernet

# Generate or load encryption key
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

# Create tables if they don't exist
c.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY, password_hash TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS passwords
             (service TEXT, username TEXT, password TEXT, user TEXT)''')

conn.commit()
conn.close()

# Hashing function for passwords
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Registration function
def register_user():
    username = simpledialog.askstring("Register", "Enter a username:")
    password = simpledialog.askstring("Register", "Enter a password:", show="*")

    if not username or not password:
        messagebox.showwarning("Input Error", "Both fields are required")
        return

    hashed_password = hash_password(password)

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "User registered successfully")
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists")
    finally:
        conn.close()

# Login function
def login_user():
    global current_user
    username = simpledialog.askstring("Login", "Enter your username:")
    password = simpledialog.askstring("Login", "Enter your password:", show="*")

    if not username or not password:
        messagebox.showwarning("Input Error", "Both fields are required")
        return

    hashed_password = hash_password(password)

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, hashed_password))
    user = c.fetchone()
    conn.close()

    if user:
        current_user = username
        messagebox.showinfo("Success", "Login successful")
        root.deiconify()  # Show the main window
        login_window.destroy()  # Close the login window
    else:
        messagebox.showerror("Error", "Invalid username or password")

# Adding the current user to the password table
def add_password():
    if not current_user:
        messagebox.showwarning("Authentication Error", "Please login first")
        return

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
    c.execute("INSERT INTO passwords (service, username, password, user) VALUES (?, ?, ?, ?)", 
              (service, username, encrypted_password, current_user))
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

# Function to view passwords (filtered by user)
def view_passwords():
    if not current_user:
        messagebox.showwarning("Authentication Error", "Please login first")
        return

    conn = sqlite3.connect('passwords.db')
    c = conn.cursor()
    c.execute("SELECT * FROM passwords WHERE user = ?", (current_user,))
    rows = c.fetchall()
    conn.close()

    view_window = tk.Toplevel()
    view_window.title("View Passwords")

    for i, row in enumerate(rows):
        service, username, encrypted_password, user = row
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        tk.Label(view_window, text=f"Service: {service}").grid(row=i, column=0)
        tk.Label(view_window, text=f"Username: {username}").grid(row=i, column=1)
        tk.Label(view_window, text=f"Password: {decrypted_password}").grid(row=i, column=2)
        tk.Button(view_window, text="Update", command=lambda s=service: update_password(s)).grid(row=i, column=3)
        tk.Button(view_window, text="Delete", command=lambda s=service: delete_password(s)).grid(row=i, column=4)

# Update and delete functions remain the same, filtering by current user

# Initial login window
current_user = None

login_window = tk.Tk()
login_window.title("Login")

tk.Button(login_window, text="Register", command=register_user).grid(row=0, column=0, columnspan=2)
tk.Button(login_window, text="Login", command=login_user).grid(row=1, column=0, columnspan=2)

login_window.mainloop()

# Main application window (hidden until login)
root = tk.Tk()
root.title("Password Manager")
root.withdraw()  # Hide main window until login

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

