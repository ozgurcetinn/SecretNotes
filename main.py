from tkinter import *
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import base64
import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# create the screen
screen = Tk()
screen.config(pady=10)
screen.title("Secret Notes")
screen.maxsize(width=700, height=700)

# add top secret image
image_path = "topsecret.jpg"
image = Image.open(image_path)
image.thumbnail((100, 100), Image.LANCZOS)
photo = ImageTk.PhotoImage(image)

# Create a label to hold the image
panel = Label(screen, image=photo)
panel.pack(side="top", fill="both", expand="no")

# Create a label than an entry for user to take notes title
title_label = Label(text="Enter Your Note Title: ", width=50, pady=10, font=("Arial", 20))
title_label.pack()

# title Entry
title_entry = Entry(font=("Arial", 20), width=25)
title_entry.pack()

# Create a text label for secret texts
secret_text = Text(width=60, height=15, padx=10, pady=20)
secret_text.pack()

# Create a label than an entry for master key
masterkey_label = Label(text="Enter your masterkey: ", font=("Arial", 20), pady=10)
masterkey_entry = Entry(width=50, show="*") #masked the masterkey
masterkey_label.pack()
masterkey_entry.pack()

# Function to derive a key from the master key
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encryption function using cryptography.fernet
def encrypt():
    note_title = title_entry.get()
    note_content = secret_text.get("1.0", END).strip()
    master_key = masterkey_entry.get()

    # Generate a random salt
    salt = os.urandom(16)

    # Derive a key from the master key using the salt
    key = derive_key(master_key, salt)
    cipher_suite = Fernet(key)

    # Encrypt the note content
    encrypted_content = cipher_suite.encrypt(note_content.encode())

    # Append the note title, salt, and encrypted content to the file
    with open("notes.txt", "ab") as file:
        file.write(note_title.encode() + b"\n" + salt + b"\n" + encrypted_content + b"\n---\n")

    # Clear the text fields
    title_entry.delete(0, END)
    secret_text.delete("1.0", END)
    masterkey_entry.delete(0, END)
    print(f"Encrypted content for '{note_title}' saved to 'notes.txt'.")

# Decryption function using cryptography.fernet
def decrypt():
    note_title = title_entry.get()
    master_key = masterkey_entry.get()

    try:
        with open("notes.txt", "rb") as file:
            data = file.read().split(b"\n---\n")

        for entry in data:
            if entry:
                entry_parts = entry.split(b"\n")
                if len(entry_parts) >= 3:
                    title, salt, encrypted_content = entry_parts[0], entry_parts[1], entry_parts[2]
                    if title.decode() == note_title:
                        # Derive a key from the master key using the salt
                        key = derive_key(master_key, salt)
                        cipher_suite = Fernet(key)

                        # Decrypt the content
                        decrypted_content = cipher_suite.decrypt(encrypted_content).decode()

                        # Clear the text widget and display the decrypted content
                        secret_text.delete("1.0", END)
                        secret_text.insert("1.0", decrypted_content)
                        print(f"Decrypted content for '{note_title}' retrieved.")
                        return

        print(f"No matching note found for title '{note_title}'.")
    except Exception as e:
        print(f"Error decrypting: {str(e)}")

# button for save and encrypt
encrypt_button = Button(text="Save & Encrypt", pady=2, width=20, command=encrypt, font="15" "Arial")
encrypt_button.pack()

# Button for decryption
decrypt_button = Button(text="Decrypt", width=20, command=decrypt, font="15" "Arial")
decrypt_button.pack()

screen.mainloop()
