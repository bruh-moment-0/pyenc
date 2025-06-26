from tkinter import Tk, Label, Button, Entry, messagebox, filedialog, DISABLED, NORMAL, END
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import subprocess
import py_compile
import platform
import base64
import shutil
import json
import sys
import os
import tempfile

BASEDIR = os.path.dirname(os.path.abspath(__file__))
SYSTEM_OS = platform.system()
KDF_ITERATIONS = 100_000
KEY_LENGTH = 32
IV_LENGTH = 16
SALT_LENGTH = 16

def byte2text(byte_text):
    return byte_text.decode('utf-8')

def write(name, data):
    with open(name, "w") as f:
        f.write(data)

def read(name):
    with open(name, 'r') as f:
        return f.read()

def readb64(name):
    with open(name, 'rb') as f:
        return base64.b64encode(f.read()).decode('ascii')

def writeb64(data, name):
    with open(name, 'wb') as f:
        f.write(base64.b64decode(data.encode('ascii')))

def remove(name):
    if os.path.exists(name):
        os.remove(name)

def compilescript(name, out):
    py_compile.compile(name, cfile=out)

def encryptAESCBC(data, password):
    salt = get_random_bytes(SALT_LENGTH)
    iv = get_random_bytes(IV_LENGTH)
    key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=KDF_ITERATIONS)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data_bytes = data.encode('utf-8')
    pad_len = AES.block_size - (len(data_bytes) % AES.block_size)
    padding = bytes([pad_len] * pad_len)
    padded_data = data_bytes + padding
    ciphertext = cipher.encrypt(padded_data)
    return base64.b64encode(ciphertext).decode(), base64.b64encode(salt).decode(), base64.b64encode(iv).decode()

def decryptAESCBC(ciphertext_b64, password, salt_b64, iv_b64):
    ciphertext = base64.b64decode(ciphertext_b64)
    salt = base64.b64decode(salt_b64)
    iv = base64.b64decode(iv_b64)
    key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=KDF_ITERATIONS)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext)
    pad_length = decrypted_data[-1]
    if pad_length < 1 or pad_length > AES.block_size:
        raise ValueError("Invalid padding length. Corrupted data or wrong password.")
    if not all(byte == pad_length for byte in decrypted_data[-pad_length:]):
        raise ValueError("Invalid padding bytes. Corrupted data or wrong password.")
    return decrypted_data[:-pad_length].decode('utf-8')

def selectfile():
    filepath = filedialog.askopenfilename(
        title="select a .py, .pyc or a .pyenc file",
        initialdir=BASEDIR,
        defaultextension=".py",
        filetypes=[("Python File", "*.py"), ("Compiled Python File", "*.pyc"), ("Encrypted Python File", "*.pyenc")]
    )
    if not filepath:
        messagebox.showerror("error", "no file selected in the selector!")
        return
    file_path_entry.config(state=NORMAL)
    file_path_entry.delete(0, END)
    file_path_entry.insert(0, filepath)
    file_path_entry.config(state=DISABLED)
    _, ext = os.path.splitext(filepath)
    ext = ext.lower()
    ext = ext[1:] if ext.startswith('.') else ext
    messagebox.showinfo("success", f"{ext} file has been selected")

def create():
    infilepath = file_path_entry.get()
    if not infilepath:
        messagebox.showerror("error", "select file first!")
        return
    _, ext = os.path.splitext(infilepath)
    ext = ext.lower()
    if ext == ".pyenc":
        messagebox.showerror("error", "you cant create a already created .pyenc!")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("error", "no password!")
        return
    outfilepath = filedialog.asksaveasfilename(
        title="save a .pyenc file",
        initialdir=BASEDIR,
        defaultextension=".pyenc",
        filetypes=[("Encrypted Python File", "*.pyenc")]
    )
    if not outfilepath:
        messagebox.showerror("error", "no output file selected!")
        return
    out_file_path_entry.config(state=NORMAL)
    out_file_path_entry.delete(0, END)
    out_file_path_entry.insert(0, outfilepath)
    out_file_path_entry.config(state=DISABLED)
    if ext == ".py":
        tempnameout = tempfile.mktemp(suffix=".pyc")
        compilescript(infilepath, tempnameout)
        script = readb64(tempnameout)
        remove(tempnameout)
    else:
        script = readb64(infilepath)
    cipher, salt, iv = encryptAESCBC(script, password)
    data = {
        "c": cipher,
        "s": salt,
        "i": iv,
        "v": sys.version,
    }
    write(outfilepath, json.dumps(data))
    messagebox.showinfo("success", f"{outfilepath} created")

def run():
    infilepath = file_path_entry.get()
    if not infilepath:
        messagebox.showerror("error", "select file first!")
        return
    _, ext = os.path.splitext(infilepath)
    ext = ext.lower()
    if ext != ".pyenc":
        messagebox.showerror("error", "only .pyenc files can be ran!")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("error", "no password!")
        return
    try:
        data = json.loads(read(infilepath))
        current_version = sys.version
        saved_version = data.get("v", "")
        if saved_version != current_version:
            messagebox.showwarning(
                "Version mismatch",
                f"Warning: The encrypted file was created with Python version:\n{saved_version}\n\n"
                f"You are running Python version:\n{current_version}\n\n"
                "This may cause compatibility issues."
            )
        decrypted_b64 = decryptAESCBC(data["c"], password, data["s"], data["i"])
        temp_fd, tempname = tempfile.mkstemp(suffix=".pyc")
        os.close(temp_fd)
        writeb64(decrypted_b64, tempname)
        path_abs = os.path.abspath(tempname)
        cmd = ["python", path_abs]
        proc = None
        if SYSTEM_OS == "Windows":
            proc = subprocess.Popen(["python", path_abs], creationflags=subprocess.CREATE_NEW_CONSOLE)
        elif SYSTEM_OS == "Darwin":
            script = f'''
            tell application "Terminal"
                activate
                do script "python '{path_abs}'"
            end tell
            '''
            subprocess.Popen(["osascript", "-e", script])
            proc = None  # no way to wait here
        elif SYSTEM_OS == "Linux":
            terms = {
                "lxterminal": ["lxterminal", "-e", *cmd],
                "gnome-terminal": ["gnome-terminal", "--", "bash", "-c", f'{" ".join(cmd)}; exec bash'],
                "konsole": ["konsole", "-e", "bash", "-c", f'{" ".join(cmd)}; exec bash'],
                "x-terminal-emulator": ["x-terminal-emulator", "-e", *cmd],
                "xterm": ["xterm", "-e", *cmd],
            }
            for term, c in terms.items():
                if shutil.which(term):
                    proc = subprocess.Popen(c)
                    break
        if proc:
            proc.wait()
        remove(tempname)
    except Exception as e:
        messagebox.showerror("error", f"decryption or execution failed: {e}")

root = Tk()
root.title("tkinter pyenc v1")
Label(root, text="pyenc v1").grid(row=0, column=0, columnspan=3)
Label(root, text="input path").grid(row=1, column=0)
Button(root, text="select file (.py, .pyc, .pyenc)", command=selectfile).grid(row=1, column=1)
file_path_entry = Entry(root, width=80)
file_path_entry.grid(row=1, column=2)
file_path_entry.config(state=DISABLED)
Label(root, text="output path").grid(row=2, column=0)
out_file_path_entry = Entry(root, width=107)
out_file_path_entry.grid(row=2, column=1, columnspan=2)
out_file_path_entry.config(state=DISABLED)
Label(root, text="password").grid(row=3, column=0)
password_entry = Entry(root, width=107)
password_entry.grid(row=3, column=1, columnspan=2)
Label(root, text="options").grid(row=4, column=0)
Button(root, text="create .pyenc", command=create).grid(row=4, column=1)
Button(root, text="run selected .pyenc", command=run).grid(row=4, column=2)
root.mainloop()
