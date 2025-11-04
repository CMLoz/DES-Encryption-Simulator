# DES encrypt/decrypt GUI — small tkinter app.
# Inputs: key (text), paragraph (plaintext or base64 ciphertext)
# Outputs: base64 ciphertext (encrypt) or plaintext (decrypt)

import base64
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

try:
    from Crypto.Cipher import DES
except Exception:
    DES = None


BLOCK_SIZE = 8


def pkcs5_pad(data: bytes) -> bytes:
    # Pad bytes to 8-byte blocks (PKCS#5)
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len]) * pad_len


def pkcs5_unpad(data: bytes) -> bytes:
    # Remove PKCS#5 padding
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def normalize_key(key_str: str) -> bytes:
    # Convert user key to exactly 8 bytes (pad or truncate)
    k = key_str.encode("utf-8")
    if len(k) < 8:
        k = k.ljust(8, b" ")
    return k[:8]


def encrypt(plaintext: str, key_str: str) -> str:
    # Encrypt plaintext and return base64 ciphertext
    if DES is None:
        raise RuntimeError("pycryptodome is not installed. See requirements.txt")
    key = normalize_key(key_str)
    cipher = DES.new(key, DES.MODE_ECB)
    data = plaintext.encode("utf-8")
    ct = cipher.encrypt(pkcs5_pad(data))
    return base64.b64encode(ct).decode("utf-8")


def decrypt(b64cipher: str, key_str: str) -> str:
    # Decrypt base64 ciphertext and return plaintext
    if DES is None:
        raise RuntimeError("pycryptodome is not installed. See requirements.txt")
    key = normalize_key(key_str)
    cipher = DES.new(key, DES.MODE_ECB)
    try:
        ct = base64.b64decode(b64cipher)
    except Exception as e:
        raise ValueError("Input is not valid base64") from e
    pt = pkcs5_unpad(cipher.decrypt(ct))
    return pt.decode("utf-8", errors="replace")


class DesApp:
    # GUI class: build widgets and connect actions
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("DES Encrypt/Decrypt")

        frm = tk.Frame(root)
        frm.pack(padx=8, pady=8, fill=tk.BOTH, expand=True)

        tk.Label(frm, text="Key (8 bytes will be used, padded/truncated):").grid(row=0, column=0, sticky=tk.W)
        self.key_entry = tk.Entry(frm, width=40)
        self.key_entry.grid(row=0, column=1, sticky=tk.W)

        self.mode_var = tk.StringVar(value="encrypt")
        tk.Radiobutton(frm, text="Encrypt", variable=self.mode_var, value="encrypt").grid(row=1, column=0, sticky=tk.W)
        tk.Radiobutton(frm, text="Decrypt", variable=self.mode_var, value="decrypt").grid(row=1, column=1, sticky=tk.W)

        tk.Label(frm, text="Input paragraph (plaintext or base64 ciphertext):").grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(8, 0))
        self.input_text = scrolledtext.ScrolledText(frm, width=80, height=12)
        self.input_text.grid(row=3, column=0, columnspan=2, pady=(0, 8))

        btn_frame = tk.Frame(frm)
        btn_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W)

        tk.Button(btn_frame, text="Run", command=self.run).grid(row=0, column=0, padx=4)
        tk.Button(btn_frame, text="Open File (for decrypt)", command=self.open_file).grid(row=0, column=1, padx=4)
        tk.Button(btn_frame, text="Save Output", command=self.save_output).grid(row=0, column=2, padx=4)
        tk.Button(btn_frame, text="Clear", command=self.clear).grid(row=0, column=3, padx=4)

        tk.Label(frm, text="Output:").grid(row=5, column=0, columnspan=2, sticky=tk.W)
        self.output_text = scrolledtext.ScrolledText(frm, width=80, height=12)
        self.output_text.grid(row=6, column=0, columnspan=2, pady=(0, 8))

        self.status = tk.Label(frm, text="Ready", anchor=tk.W)
        self.status.grid(row=7, column=0, columnspan=2, sticky=tk.W+tk.E)

        # shows the path of last saved file (if any)
        self.last_saved_var = tk.StringVar(value="")
        tk.Label(frm, textvariable=self.last_saved_var, anchor=tk.W, fg="blue").grid(row=8, column=0, columnspan=2, sticky=tk.W)

    def set_status(self, msg: str):
        # update status line
        self.status.config(text=msg)

    def run(self):
        # read UI values
        mode = self.mode_var.get()
        key = self.key_entry.get()
        data = self.input_text.get("1.0", tk.END).strip()
        if not key:
            messagebox.showwarning("Missing key", "Please enter a key (will be padded or truncated to 8 bytes).")
            return
        if not data:
            messagebox.showwarning("Missing data", "Please enter text to encrypt or decrypt.")
            return

        # run encrypt or decrypt and show output
        try:
            if mode == "encrypt":
                out = encrypt(data, key)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, out)
                self.set_status("Encryption complete. You can save the output to a file.")
            else:
                out = decrypt(data, key)
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert(tk.END, out)
                self.set_status("Decryption complete.")
        except Exception as e:
            # show error
            messagebox.showerror("Error", str(e))
            self.set_status("Error: " + str(e))

    def save_output(self):
        out = self.output_text.get("1.0", tk.END).strip()
        if not out:
            messagebox.showinfo("No output", "There is no output to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(out)
            self.set_status(f"Saved output to: {path}")
            # display last saved path
            self.last_saved_var.set(f"Last saved: {path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))
            self.set_status("Save error: " + str(e))

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert(tk.END, content)
            self.set_status(f"Loaded file: {path}")
        except Exception as e:
            messagebox.showerror("Open error", str(e))
            self.set_status("Open error: " + str(e))

    def clear(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)
        self.set_status("Cleared")
        # clear last saved path
        self.last_saved_var.set("")


def main():
    root = tk.Tk()
    app = DesApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
