import sys
import os
import json
import requests
import base64
import logging
from local_commands import *
from anonymous_api_commands import rep_get_file
from utils import *


logging.basicConfig(format="  [%(levelname)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def rep_add_subject(state, session_file, username, name, email, credentials_file):
    # Read credentials file to access the public key
    with open(credentials_file, "r") as f:
        keys_file = json.load(f)

    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "new_subject": {
            "username": username,
            "name": name,
            "email": email,
            "public_key": keys_file["PUBLIC_KEY"],
        },
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/subject/create"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"Subject {username} added successfully.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_suspend_subject(state, session_file, username):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "subject_to_suspend": username,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/subjects/suspend"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"Subject {username} has been suspended.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_activate_subject(state, session_file, username):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "subject_to_activate": username,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/subjects/activate"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"Subject {username} has been activated.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_add_role(state, session_file, role):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "role": role,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/add"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"Role {role} created successfully.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_suspend_role(state, session_file, role):
    # O role do manager não pode ser suspenso
    if role == "manager":
        logger.error("manager role can't be suspended")
        sys.exit(1)

    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "role": role,
        "operation": "suspend",
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/change/status"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"Role {role} status changed successfully.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_reactivate_role(state, session_file, role):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "role": role,
        "operation": "reactivate",
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/change/status"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"Role {role} status changed successfully.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_add_permission(state, session_file, role, username_or_permission):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "role": role,
        "username_or_permission": username_or_permission,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/add/permission"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"{response.json().get("message")}.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_remove_permission(state, session_file, role, username_or_permission):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "role": role,
        "username_or_permission": username_or_permission,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/remove/permission"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info(f"{response.json().get("message")}.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_add_doc(state, session_file, document_name, file_path):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Read document file content
    try:
        with open(file_path, "rb") as f:
            file_content = f.read()
    except FileNotFoundError:
        logger.error(f"File {file_path} not found.")
        sys.exit(1)
    # Calculate file handle (hash value of file content)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_content)
    file_hash = digest.finalize()

    # Generate a random 128 bit key and encrypt the file content
    secret_key = os.urandom(16)
    encrypted_document_content, document_iv = encrypt_data_AES_CBC(
        file_content, secret_key
    )

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "secret_key": base64.b64encode(secret_key).decode(),
        "document_iv": base64.b64encode(document_iv).decode(),
        "document_name": document_name,
        "file_handle": base64.b64encode(file_hash).decode(),
        "algorithm": "AES-CBC",
    }

    final_payload = prepare_final_payload(
        base_payload, session_data, encrypted_document_content
    )
    url = f"http://{state['REP_ADDRESS']}/doc/create"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info("Document added successfully")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_get_doc_metadata(state, session_file, document_name=None):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "document_name": document_name,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/doc/get/metadata"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        data = response.json()
        valid_payload = validate_payload(data, session_data)
        if "error" in valid_payload:
            logger.error(valid_payload["error"])
            sys.exit(1)
        else:
            decrypted_payload = valid_payload["success"]

        pretty_print("Metadata", json.dumps(decrypted_payload), True)
        return json.dumps(decrypted_payload)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


# Note: Commented code was used to stop the other functions outputs,
# However I think it might be important in case of an error, to know what it was
def rep_get_doc_file(state, session_file, document_name, output_file=None):
    # original_stdout = sys.stdout
    # sys.stdout = open(os.devnull, "w")

    # Get Metadata
    document_metadata = rep_get_doc_metadata(state, session_file, document_name)
    file_handle = json.loads(document_metadata)["file_handle"]

    # Get file
    encrypted_file_content = rep_get_file(state, file_handle)
    file_content = rep_decrypt_file(encrypted_file_content, document_metadata)
    # sys.stdout = original_stdout

    if output_file:
        with open(output_file, "w") as f:
            f.write(file_content)
    else:
        pretty_print(title="File Content", message=file_content)
    sys.exit(0)


def rep_delete_doc(state, session_file, document_name):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "document_name": document_name,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/doc/clear/file-handle"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info("Document deleted successfully")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_acl_doc(state, session_file, document_name, operation, role, permission):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define base payload
    base_payload = {
        "organization": session_data["organization"],
        "username": session_data["username"],
        "document_name": document_name,
        "operation": operation,
        "role": role,
        "permission": permission,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/doc/change/acl"
    response = requests.post(url, json=final_payload)
    # Update nonce
    with open(session_file, "w") as sf:
        json.dump(session_data, sf)

    if response.status_code == 200:
        logger.info("Document ACL updated successfully")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)
