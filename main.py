import tkinter as tk
from tkinter import ttk
import numpy as np
import math

# Caesar Cipher Functions
def caesar_cipher_encrypt(plaintext, shift):
    encrypted_text = ""
    for char in plaintext:
        if char.isalpha():
            shift_amount = shift % 26
            new_char = chr(((ord(char.upper()) - 65 + shift_amount) % 26) + 65)
            encrypted_text += new_char if char.isupper() else new_char.lower()
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)

# Hill Cipher Functions
def generate_key_matrix(key):
    key = key.replace(" ", "").upper()
    key_len = len(key)
    size = int(math.sqrt(key_len))
    key_matrix = []

    for i in range(0, key_len, size):
        row = [ord(char) - ord('A') for char in key[i:i+size]]
        key_matrix.append(row)

    return np.array(key_matrix)

def get_inverse_matrix(matrix):
    det = int(round(np.linalg.det(matrix)))
    det_inv = 0
    for i in range(26):
        if (det * i) % 26 == 1:
            det_inv = i
            break
    adjugate = np.round(np.linalg.inv(matrix) * det).astype(int)
    inverse = (det_inv * adjugate) % 26
    return inverse

def matrix_to_string(matrix):
    string = ""
    for row in matrix:
        for value in row:
            string += chr(value % 26 + ord('A'))
    return string

def hill_cipher_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    key_matrix = generate_key_matrix(key)

    if len(plaintext) % key_matrix.shape[0] != 0:
        plaintext += 'X' * (key_matrix.shape[0] - len(plaintext) % key_matrix.shape[0])

    plaintext_matrix = np.array([ord(char) - ord('A') for char in plaintext])
    plaintext_matrix = plaintext_matrix.reshape(-1, key_matrix.shape[0])

    ciphertext_matrix = np.dot(plaintext_matrix, key_matrix) % 26

    ciphertext = matrix_to_string(ciphertext_matrix)

    return ciphertext

def hill_cipher_decrypt(ciphertext, key):
    ciphertext = ciphertext.replace(" ", "").upper()
    key_matrix = generate_key_matrix(key)
    key_inverse = get_inverse_matrix(key_matrix)

    ciphertext_matrix = np.array([ord(char) - ord('A') for char in ciphertext])
    ciphertext_matrix = ciphertext_matrix.reshape(-1, key_matrix.shape[0])

    plaintext_matrix = np.dot(ciphertext_matrix, key_inverse) % 26

    plaintext = matrix_to_string(plaintext_matrix)

    return plaintext

# Playfair Cipher Functions
def generate_playfair_matrix(keyword):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix = []
    used_chars = set()
    
    for char in keyword.upper():
        if char not in used_chars and char in alphabet:
            matrix.append(char)
            used_chars.add(char)
    
    for char in alphabet:
        if char not in used_chars:
            matrix.append(char)
            used_chars.add(char)
    
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_cipher_encrypt(plaintext, keyword):
    plaintext = plaintext.upper().replace("J", "I")
    digraphs = []
    i = 0
    
    while i < len(plaintext):
        a = plaintext[i]
        b = plaintext[i + 1] if i + 1 < len(plaintext) else 'X'
        
        if a == b:
            digraphs.append(a + 'X')
            i += 1
        else:
            digraphs.append(a + b)
            i += 2
    
    if len(digraphs[-1]) == 1:
        digraphs[-1] += 'X'
    
    matrix = generate_playfair_matrix(keyword)
    ciphertext = ""
    
    for digraph in digraphs:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])
        
        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    
    return ciphertext

def playfair_cipher_decrypt(ciphertext, keyword):
    matrix = generate_playfair_matrix(keyword)
    digraphs = [ciphertext[i:i+2] for i in range(0, len(ciphertext), 2)]
    plaintext = ""
    
    for digraph in digraphs:
        row1, col1 = find_position(matrix, digraph[0])
        row2, col2 = find_position(matrix, digraph[1])
        
        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    
    return plaintext

# User Interface Functions
def encrypt_caesar():
    plaintext = caesar_plaintext.get()
    shift = int(caesar_shift.get())
    encrypted = caesar_cipher_encrypt(plaintext, shift)
    caesar_output.set(encrypted)

def decrypt_caesar():
    ciphertext = caesar_plaintext.get()
    shift = int(caesar_shift.get())
    decrypted = caesar_cipher_decrypt(ciphertext, shift)
    caesar_output.set(decrypted)

def encrypt_hill():
    plaintext = hill_plaintext.get()
    key = hill_key.get()
    encrypted = hill_cipher_encrypt(plaintext, key)
    hill_output.set(encrypted)

def decrypt_hill():
    ciphertext = hill_plaintext.get()
    key = hill_key.get()
    decrypted = hill_cipher_decrypt(ciphertext, key)
    hill_output.set(decrypted)

def encrypt_playfair():
    plaintext = playfair_plaintext.get()
    keyword = playfair_keyword.get()
    encrypted = playfair_cipher_encrypt(plaintext, keyword)
    playfair_output.set(encrypted)

def decrypt_playfair():
    ciphertext = playfair_plaintext.get()
    keyword = playfair_keyword.get()
    decrypted = playfair_cipher_decrypt(ciphertext, keyword)
    playfair_output.set(decrypted)

# Main Application Window
root = tk.Tk()
root.title("Cryptographic Ciphers")

notebook = ttk.Notebook(root)
notebook.pack(pady=10, expand=True)

# Caesar Cipher Tab
caesar_frame = ttk.Frame(notebook, width=400, height=400)
caesar_frame.pack(fill="both", expand=True)

caesar_plaintext = tk.StringVar()
caesar_shift = tk.StringVar()
caesar_output = tk.StringVar()

ttk.Label(caesar_frame, text="Plaintext/Ciphertext:").pack(pady=5)
ttk.Entry(caesar_frame, textvariable=caesar_plaintext).pack(pady=5)

ttk.Label(caesar_frame, text="Shift:").pack(pady=5)
ttk.Entry(caesar_frame, textvariable=caesar_shift).pack(pady=5)

ttk.Button(caesar_frame, text="Encrypt", command=encrypt_caesar).pack(pady=5)
ttk.Button(caesar_frame, text="Decrypt", command=decrypt_caesar).pack(pady=5)

ttk.Label(caesar_frame, text="Output:").pack(pady=5)
ttk.Entry(caesar_frame, textvariable=caesar_output).pack(pady=5)

notebook.add(caesar_frame, text="Caesar Cipher")

# Hill Cipher Tab
hill_frame = ttk.Frame(notebook, width=400, height=400)
hill_frame.pack(fill="both", expand=True)

hill_plaintext = tk.StringVar()
hill_key = tk.StringVar()
hill_output = tk.StringVar()

ttk.Label(hill_frame, text="Plaintext/Ciphertext:").pack(pady=5)
ttk.Entry(hill_frame, textvariable=hill_plaintext).pack(pady=5)

ttk.Label(hill_frame, text="Key (3x3):").pack(pady=5)
ttk.Entry(hill_frame, textvariable=hill_key).pack(pady=5)

ttk.Button(hill_frame, text="Encrypt", command=encrypt_hill).pack(pady=5)
ttk.Button(hill_frame, text="Decrypt", command=decrypt_hill).pack(pady=5)

ttk.Label(hill_frame, text="Output:").pack(pady=5)
ttk.Entry(hill_frame, textvariable=hill_output).pack(pady=5)

notebook.add(hill_frame, text="Hill Cipher")

# Playfair Cipher Tab
playfair_frame = ttk.Frame(notebook, width=400, height=400)
playfair_frame.pack(fill="both", expand=True)

playfair_plaintext = tk.StringVar()
playfair_keyword = tk.StringVar()
playfair_output = tk.StringVar()

ttk.Label(playfair_frame, text="Plaintext/Ciphertext:").pack(pady=5)
ttk.Entry(playfair_frame, textvariable=playfair_plaintext).pack(pady=5)

ttk.Label(playfair_frame, text="Keyword:").pack(pady=5)
ttk.Entry(playfair_frame, textvariable=playfair_keyword).pack(pady=5)

ttk.Button(playfair_frame, text="Encrypt", command=encrypt_playfair).pack(pady=5)
ttk.Button(playfair_frame, text="Decrypt", command=decrypt_playfair).pack(pady=5)

ttk.Label(playfair_frame, text="Output:").pack(pady=5)
ttk.Entry(playfair_frame, textvariable=playfair_output).pack(pady=5)

notebook.add(playfair_frame, text="Playfair Cipher")

root.mainloop()
