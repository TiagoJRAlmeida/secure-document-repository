import os
import sys
import json
import requests
import base64
import logging
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from utils import *


logging.basicConfig(format="[%(levelname)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def rep_create_org(state, organization, username, name, email, credentials_file):
    # Get public Key of the user and prepare the payload to send
    if os.path.isfile(credentials_file):
        with open(credentials_file, "r") as f:
            try:
                public_key = json.load(f)["PUBLIC_KEY"]
            except json.JSONDecodeerror:
                logger.error("Credentials file is not in a valid JSON format.")
                sys.exit(1)
    else:
        logger.error("Credentials file does not exist.")
        sys.exit(1)

    # Prepare payload to send
    payload = {
        "name": organization,
        "owner": {
            "username": username,
            "full_name": name,
            "email": email,
            "public_key": public_key,
        },
    }

    # Send the payload to the server API
    url = f"http://{state["REP_ADDRESS"]}/organization/create"
    response = requests.post(url, json=payload)

    # Check response status
    if response.status_code == 201:
        logger.info("Organization created successfully.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_list_orgs(state):
    url = f"http://{state['REP_ADDRESS']}/organization/list"
    response = requests.get(url)

    if response.status_code == 200:
        orgs = response.json()
        tittle = "Organizations"
        if not orgs:
            message = "No current organizations"
        else:
            message = ""
            for index, (name, owner) in enumerate(orgs.items()):
                message += f"\tOrganization {index + 1}: {name}, Created by {owner}\n"
        pretty_print(tittle, message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_create_session(
    state, organization, username, password, credentials_file, session_file
):
    # Open credentials file
    with open(credentials_file, "r") as f:
        keys_file = json.load(f)

    # Generate a random 256 bits key and divide it in 2
    new_symmetric_key = os.urandom(32)  # 256 bits
    new_encryption_key = new_symmetric_key[0:16]
    new_integrity_key = new_symmetric_key[16:]

    # Load the repository public key saved on the state dict as text in PEM format
    rep_public_key = load_pem_public_key(state["REP_PUB_KEY"].encode())

    # Encrypt the new key (256bits) with REP_PUBLIC_KEY
    encrypted_key = rep_public_key.encrypt(
        new_symmetric_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Load client private key from credentials file and sign the new encrypted key
    client_private_key = load_pem_private_key(
        base64.b64decode(keys_file["ENCRYPTED_PRIVATE_KEY"]), password=password.encode()
    )
    encrypted_key_signature = client_private_key.sign(
        encrypted_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )

    # Calculate the HMAC (Used to verify integrity)
    hmac_signature = calculate_hmac(encrypted_key, new_integrity_key)

    # Generate a random 128 bit nonce
    nonce = os.urandom(16)

    # Prepare the base payload
    base_payload = {
        "organization_name": organization,
        "username": username,
        "public_key": keys_file["PUBLIC_KEY"],
    }

    # Encrypt the base payload with the new symmetric key to protect against MITM attacks
    encrypted_base_payload, iv = encrypt_data_AES_CBC(
        json.dumps(base_payload).encode(), new_encryption_key
    )

    payload = {
        "encrypted_base_payload": base64.b64encode(encrypted_base_payload).decode(),
        "iv": base64.b64encode(iv).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "signature": base64.b64encode(encrypted_key_signature).decode(),
    }

    # Send the payload to server API endpoint
    url = f"http://{state['REP_ADDRESS']}/session/create"
    response = requests.post(url, json=payload)

    # If everything went correctly, save the session data on a file for later use.
    if response.status_code == 200:
        data = response.json()
        received_session_id = data["session_id"]
        received_expiration_time = data["expiration_time"]

        session_data = {
            "session_id": received_session_id,
            "organization_name": organization,
            "username": username,
            "keys": {
                "encryption_key": base64.b64encode(new_encryption_key).decode(),
                "integrity_key": base64.b64encode(new_integrity_key).decode(),
                "nonce": base64.b64encode(nonce).decode(),
            },
            "roles": [],
            "expiration_time": received_expiration_time,
        }

        with open(session_file, "w") as f:
            json.dump(session_data, f)

        logger.info(f"Operation successful. Session data saved in {session_file}")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_get_file(state, file_handle, output_file=None):
    # Define payload
    payload = {"file_handle": file_handle}

    # Send paylod to server API endpoint
    url = f"http://{state['REP_ADDRESS']}/doc/get/file_by_handle"
    response = requests.post(url, json=payload)

    # If file exists
    if response.status_code == 200:
        logger.info("File retrieved successfully.")
        data = response.json()
        encrypted_file_content = base64.b64decode(data["encrypted_file_content"])

        # If an output file was passed, write to it, otherwise print to stdout and return it.
        if output_file:
            with open(output_file, "wb") as f:
                f.write(encrypted_file_content)
            sys.exit(0)
        else:
            print(encrypted_file_content)
            return encrypted_file_content
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)
