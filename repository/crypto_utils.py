import os
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


def calculate_hmac(data, key):
    hmac_computer = crypto_hmac.HMAC(key, hashes.SHA256())
    hmac_computer.update(data)
    hmac_signature = hmac_computer.finalize()
    return hmac_signature


def decrypt_data_AES_CBC(encrypted_data, key, iv):
    # Initiate AES-CBC with the key and IV received
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt and remove padding
    decrypted_padded_payload = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_payload = unpadder.update(decrypted_padded_payload) + unpadder.finalize()
    decrypted_payload = decrypted_payload.decode()

    return decrypted_payload


def encrypt_data_AES_CBC(data, key):
    # Generates a random 128 bits IV
    iv = os.urandom(16)

    # Initiate AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Add padding and encrypt it
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_payload = padder.update(data) + padder.finalize()
    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

    return encrypted_payload, iv


# Convert nonce from bytes to integer, incrementes it by 1, and returns it in bytes format again.
def calculate_next_nonce(nonce):
    nonce_int = int.from_bytes(nonce, byteorder="big")
    nonce_int += 1
    new_nonce = nonce_int.to_bytes(16, byteorder="big")
    return new_nonce

