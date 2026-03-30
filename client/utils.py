import os
import json
import base64
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import shutil


def calculate_hmac(data, key):
    hmac_computer = crypto_hmac.HMAC(key, hashes.SHA256())
    hmac_computer.update(data)
    hmac_signature = hmac_computer.finalize()
    return hmac_signature


def encrypt_data_AES_CBC(data, key):
    # Gerar um IV aleatorio de 128 bits
    iv = os.urandom(16)

    # Inicializar o AES-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Adicionar padding ao session_id serializado
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_payload = padder.update(data) + padder.finalize()

    # Cifrar os dados alinhados
    encrypted_payload = encryptor.update(padded_payload) + encryptor.finalize()

    return encrypted_payload, iv


# Retorna no formato dict
def decrypt_data_AES_CBC(encrypted_payload, key, iv):
    # Descifrar o payload
    # Inicializar o AES-CBC com a chave e o IV recebido
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decifrar o received_encrypted_payload
    decrypted_padded_payload = (
        decryptor.update(encrypted_payload) + decryptor.finalize()
    )

    # Remover o padding com PKCS7
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_payload = unpadder.update(decrypted_padded_payload) + unpadder.finalize()

    # Transformar o decryped_payload no formato correto
    decrypted_payload = json.loads(decrypted_payload.decode())

    return decrypted_payload


def calculate_next_nonce(nonce):
    # Converter o nonce de byte para int
    nonce_int = int.from_bytes(nonce, byteorder="big")

    # Incrementar o nonce
    nonce_int += 1

    # Converter para bytes novamente
    new_nonce = nonce_int.to_bytes(16, byteorder="big")

    return new_nonce


def pretty_print(title, message):
    cols = shutil.get_terminal_size().columns

    # ANSI codes mirroring the bash tput styles
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    divider = "─" * cols

    print(f"\n{divider}\n")
    print(f"  {BOLD}{title}{RESET}\n")
    for line in message.splitlines():
        print(f"  {DIM}{line}{RESET}")
    print(f"\n{divider}\n")
