# DES Encrypt/Decrypt Tkinter App

Simple Python GUI to encrypt or decrypt a paragraph using DES (ECB mode) and save/load the results to/from text files.

Requirements
- Python 3.6+
- Install dependencies from `requirements.txt` (pycryptodome)

Install

Open a terminal and run:

    python -m pip install -r requirements.txt

Run

    python app.py

Usage
- Enter an 8-byte key (shorter keys will be padded with spaces, longer keys truncated).
- Choose Encrypt or Decrypt.
- Paste your plaintext (for encrypt) or base64 ciphertext (for decrypt) into the input box.
- Click Run. Output appears in the Output box.
- Use Save Output to store the result in a text file. Use Open File to load a file into the input box.

Notes
- This example uses DES in ECB mode for simplicity. ECB and DES are not recommended for real secure applications.
- The encrypted output is base64-encoded text so it can be stored in a text file and later pasted back for decryption.
