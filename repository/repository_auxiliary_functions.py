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

    # Inicializar o AES-CBC com a chave e o IV recebido
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decifrar a encrypted_data
    decrypted_padded_payload = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remover o padding com PKCS7
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_payload = unpadder.update(decrypted_padded_payload) + unpadder.finalize()
    
    # Transformar a encrypted_data no formato correto 
    decrypted_payload = decrypted_payload.decode()

    return decrypted_payload


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


def calculate_next_nonce(nonce):
    # Converter o nonce de byte para int
    nonce_int = int.from_bytes(nonce, byteorder='big')

    # Incrementar o nonce
    nonce_int += 1

    # Converter para bytes novamente
    new_nonce = nonce_int.to_bytes(16, byteorder='big')
    
    return new_nonce