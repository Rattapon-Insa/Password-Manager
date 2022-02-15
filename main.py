import sqlite3
import hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import pyperclip
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'8732'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length = 32,
    salt = salt,
    iterations= 100000,
    backend = backend
)

encryptionKey = 0

def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)

def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)
# database code
with sqlite3.connect('Password_manager.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS password(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")


# create pop-up

def popUp(text):
    answer = simpledialog.askstring('input string', text)
    return answer

def hashPassword(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash

def firstScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x200")
    lbl = Label(window, text="create master password")
    lbl.config(anchor = CENTER)
    lbl.pack()

    txt = Entry(window, width = 20,show = "*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="re-enter password")
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()
    txt1.focus()

    lbl2 = Label(window)
    lbl2.pack()


    def savePassword():
        if txt.get() == txt1.get():
            lbl2.config(text='Password matched')
            sql = "DELETE from masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?,?)"""
            cursor.execute(insert_password,((hashedPassword, recoveryKey)))
            db.commit()
            passwordManager()
        else:
            lbl2.config(text = 'Password not match')
    btn = Button(window, text='Submit', command=savePassword)
    btn.pack(pady=10)

def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x200")
    lbl = Label(window, text="Save this key to be able to recover account")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor= CENTER)
    lbl1.pack()

    def done():
        passwordManager()


    def copyKey():
        pyperclip.copy(lbl1.cget('text'))

    btn = Button(window, text='copy key', command=copyKey)
    btn.pack(pady=10)
    btn = Button(window, text='Done', command=done)
    btn.pack(pady=10)

def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x200")
    lbl = Label(window, text="Enter recovery key")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width = 20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor= CENTER)
    lbl1.pack()


    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHER id = 1 AND recoveryKey = ?",[(recoveryKeyCheck)])
        return cursor.fetchall()
    def checkRecoverykey():
        check = getRecoveryKey()
        if check:
            firstScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text = 'Wrong password')

    btn = Button(window, text='Check key', command=checkRecoverykey)
    btn.pack(pady=10)

def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()
    window.geometry("250x150")

    lbl = Label(window, text="Enter the master password")
    lbl.config(anchor = CENTER)
    lbl.pack()

    txt = Entry(window, width = 20,show = "*")
    txt.pack()
    txt.focus()

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 and password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()
        if match:
            passwordManager()
        else:
            lbl.config(text='Wrong Password')
            txt.delete(0,'end')


    btn = Button(window, text='Submit', command=checkPassword)
    btn.pack(pady=10)

    #btn = Button(window, text='Reset Password', command=resetPassword)
    #btn.pack(pady=10)

def passwordManager():
    for widget in window.winfo_children():
        widget.destroy()
    def addEntry():
        text1 = 'Website'
        text2 = 'Username'
        text3 = 'password'

        website = encrypt(popUp(text1).encode(),encryptionKey)
        username = encrypt(popUp(text2).encode(),encryptionKey)
        password = encrypt(popUp(text3).encode(),encryptionKey)

        insert_field = """INSERT INTO password(website, username, password)
        VALUES(?,?,?)"""

        cursor.execute(insert_field, (website, username, password))
        db.commit()
        passwordManager()
    def removeEntry(input):
        cursor.execute("DELETE FROM password WHERE id = ?", (input,))
        db.commit()
        passwordManager()

    window.geometry("800x400")
    lbl = Label(window, text = 'Password Manager')
    lbl.grid(column = 1)

    btn = Button(window, text = "+", command= addEntry)
    btn.grid(column = 1, pady = 10)

    lbl = Label(window, text='Website')
    lbl.grid(row = 2, column=0, padx =80)
    lbl = Label(window, text='Username')
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text='Password')
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * FROM password")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM password")
            array = cursor.fetchall()
            if len(array) == 0:
                break

            lbl1 = Label(window, text = (decrypt(array[i][1],encryptionKey)), font = ('Helvetica', 12))
            lbl1.grid(column = 0, row = i+3)
            lbl1 = Label(window, text = (decrypt(array[i][2],encryptionKey)), font = ('Helvetica', 12))
            lbl1.grid(column = 1, row = i+3)
            lbl1 = Label(window, text = (decrypt(array[i][3],encryptionKey)), font = ('Helvetica', 12))
            lbl1.grid(column = 2, row = i+3)


            btn = Button(window, text = "Delete", command= partial(removeEntry, array[i][0]))
            btn.grid(column=3, row = i+3,pady = 10)
            i += 1

            cursor.execute("SELECT * FROM password")
            if (len(cursor.fetchall()) <= i):
                break

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    window = Tk()
    window.title("Password Manager")
    cursor.execute("SELECT * FROM masterpassword")
    if cursor.fetchall():
        loginScreen()
    else:
        firstScreen()

    window.mainloop()

