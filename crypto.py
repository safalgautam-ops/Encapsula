from Crypto.Cipher import AES 
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
import os
import struct
import hashlib

def hash_password(password):
    #encode(): Convert password to bytes if it's a string
    #sha256(): Create a SHA-256 hash object ready to compute the hash
    #digest(): Return the binary digest of the hash(as a bytes object)
    return hashlib.sha256(password.encode()).digest()

def encrypt(plaintext, password):
    salt = os.urandom(16)
    iterations = 10000
    key = PBKDF2(password, salt, dkLen=32, count=iterations)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode(), 16)
    ciphertext = cipher.encrypt(padded_data)
    password_hash = hash_password(password)  # 32 bytes
    # Pack: [password_hash (32)] [salt (16)] [iterations (4)] [iv (16)] [ciphertext] 
    #This struct.pack allows you to store or transmit the integer in a fixed-size binary format.
    # '>I' means big-endian unsigned integer: "the big end or MSB" comes first in the byte sequence
    packed = password_hash + salt + struct.pack('>I', iterations) + iv + ciphertext
    return packed

def check_password(packed, password):
    """Check if the password hash matches the stored hash in packed data."""
    stored_hash = packed[:32]
    return stored_hash == hash_password(password)

def decrypt(packed, password):
    # First 32 bytes: password hash
    salt = packed[32:48]
    iterations = struct.unpack('>I', packed[48:52])[0]
    iv = packed[52:68]
    ciphertext = packed[68:]
    key = PBKDF2(password, salt, dkLen=32, count=iterations)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    return unpad(padded_plaintext, 16).decode('utf-8')



