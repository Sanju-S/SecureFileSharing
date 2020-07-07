from Cryptodome import Random
from Cryptodome.Cipher import AES
import os


def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


def encrypt(message, key):
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


def decrypt(ciphertext, key):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return plaintext.rstrip(b"\0")


def encrypt_file(file, key):
    with open(file, 'rb') as fi:
        text = fi.read()
    enc = encrypt(text, key)
    os.remove(file)
    with open(file, 'wb') as fo:
        fo.write(enc)


def decrypt_file(file_name, key):
    with open(file_name, 'rb') as fo:
        ciphertext = fo.read()
    dec = decrypt(ciphertext, key)
    os.remove(file_name)
    with open(file_name, 'wb') as fo:
        fo.write(dec)



