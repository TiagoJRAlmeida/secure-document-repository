import sys
import json
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from utils import pretty_print, get_logger

logger = get_logger(__name__)


def rep_subject_credentials(password, credentials_file):
    # Generate RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    public_key = private_key.public_key()

    # Get Private Key in PEM format
    encrypted_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    # Get Public Key in PEM format
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Encode with base64 for JSON compatability
    payload = {
        "ENCRYPTED_PRIVATE_KEY": base64.b64encode(encrypted_private_key).decode(
            "utf-8"
        ),
        "PUBLIC_KEY": base64.b64encode(public_key_bytes).decode("utf-8"),
    }

    # Save in JSON format
    with open(credentials_file, "w") as f:
        json.dump(payload, f, indent=4)

    logger.info(f"Keys saved on file {credentials_file} !")


def rep_decrypt_file(encrypted_file, metadata):
    if os.path.isfile(encrypted_file):
        with open(encrypted_file, "rb") as f:
            encrypted_file = f.read()
    elif type(encrypted_file) == bytes:
        pass
    elif type(encrypted_file) == str:
        encrypted_file = encrypted_file.encode()

    else:
        logger.error("Encrypted file does not exist.")
        sys.exit(1)

    if os.path.isfile(metadata):
        with open(metadata, "r") as f:
            metadata = f.read()
    elif type(metadata) == str:
        pass
    else:
        logger.error("Metadata file does not exist.")
        sys.exit(1)

    try:
        metadata = json.loads(metadata)
    except json.JSONDecodeError:
        logger.error("Metadata is not a valid JSON file.")
        print(metadata)
        sys.exit(-1)

    # Get encryption key and IV from metadata file
    decrypted_key = base64.b64decode(metadata["key"])
    iv = base64.b64decode(metadata["iv"])

    # Start decryption process
    # Start AES-CBC with the received key and IV
    cipher = Cipher(algorithms.AES(decrypted_key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    # Decrypt the file
    decrypted_padded_file = decryptor.update(encrypted_file) + decryptor.finalize()

    # Remove the padding
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_file = unpadder.update(decrypted_padded_file) + unpadder.finalize()
    data = decrypted_file.decode()

    logger.info("File decrypted Successfully.")
    pretty_print(title="File Content", message=data)

    return data
