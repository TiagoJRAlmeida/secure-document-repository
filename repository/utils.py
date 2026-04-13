import os
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from crypto_utils import *


def rep_keys():
    if not os.path.exists("rep_pub_key.pem") or not os.path.exists("rep_priv_key.pem"):
        password = os.environ.get("PASSWORD", "password1234")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        ENCRYPTED_REP_PRIV_KEY = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                password.encode()
            ),
        )

        REP_PUB_KEY = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open("rep_pub_key.pem", "wb") as pubk_file:
            pubk_file.write(REP_PUB_KEY)

        with open("rep_priv_key.pem", "wb") as privk_file:
            privk_file.write(ENCRYPTED_REP_PRIV_KEY)


def load_state():
    paths = ("organizations.json", "sessions.json", "documents.json")
    state = {}
    for path in paths:
        key = os.path.splitext(path)[0]
        if os.path.exists(path):
            with open(path, "r") as f:
                state[key] = json.load(f)
        else:
            state[key] = {}
    return state


def save_state(state):
    for key, elem in state.items():
        path = key + ".json"
        with open(path, "w") as f:
            json.dump(elem, f)


def verify_session(state, data):
    session_id = data["session_id"]
    nonce = base64.b64decode(data["nonce"])

    # Verify if session ID is valid
    if session_id not in state["sessions"]:
        return {"error": "Session ID not valid"}

    # Verify is session is not expired
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][session_id]["expiration_time"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(session_id)
        return {"error": "Session expiration time reached. Create a new session."}

    # Verify if nonce is valid
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][session_id]["keys"]["nonce"])
    )
    if nonce != correct_nonce:
        return {"error": "Nonce not valid"}

    # Update nonce
    session_id = data["session_id"]
    nonce = base64.b64decode(data["nonce"])
    state["sessions"][session_id]["keys"]["nonce"] = base64.b64encode(nonce).decode()

    # If all went well
    return {"success": "Session is valid"}


def decrypt_and_verify_payload(state, data):
    session_id = data["session_id"]
    encrypted_payload = base64.b64decode(data["encrypted_payload"])
    hmac = base64.b64decode(data["hmac"])
    nonce = base64.b64decode(data["nonce"])
    iv = base64.b64decode(data["iv"])

    # Get session keys
    encryption_key = base64.b64decode(
        state["sessions"][session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][session_id]["keys"]["integrity_key"]
    )

    # Decrypt payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(encrypted_payload, encryption_key, iv)
    )

    # Verify HMAC validity
    payload_bytes = json.dumps(decrypted_payload).encode()
    if "encrypted_document_content" in data:
        encrypted_document_content = base64.b64decode(
            data["encrypted_document_content"]
        )
        message = (
            session_id.encode()
            + payload_bytes
            + iv
            + nonce
            + encrypted_document_content
        )
    else:
        message = session_id.encode() + payload_bytes + iv + nonce
    calculated_hmac = calculate_hmac(message, integrity_key)
    if calculated_hmac != hmac:
        return {"error": "HMAC not valid"}
    else:
        return {
            "success": "Payload decrypted and verified",
            "payload": decrypted_payload,
        }


def filter_doc_by_user(document, user):
    valid_document = (
        (document["name"], document["creator"], document["creation_date"])
        if document["creator"] == user
        else ()
    )
    return {"success": valid_document}


def filter_doc_by_date(document, date, relation):
    valid_document = ()
    if relation not in ["nt", "ot", "et"]:
        return {"error": "Date relation filter not valid. Must be: [nt/ot/et]"}
    else:
        condition_1 = relation == "nt" and document["creation_date"] > date
        condition_2 = relation == "ot" and document["creation_date"] < date
        condition_3 = relation == "et" and document["creation_date"] == date
        if any((condition_1, condition_2, condition_3)):
            valid_document = (
                document["name"],
                document["creator"],
                document["creation_date"],
            )
    return {"success": valid_document}


def has_permission(user_roles, organization=None, permission=None, document=None):
    if not any((organization, document)) or all((organization, document)):
        return False
    elif organization:
        for role in user_roles:
            if permission in organization["acl"][role]["permissions"]:
                return True
    else:
        for role in user_roles:
            if permission in document["acl"][role]:
                return True
    return False


def calculate_document_handle(document_name, organization_name):
    digest = hashes.Hash(hashes.SHA256())
    message = document_name.encode() + organization_name.encode()
    digest.update(message)
    document_handle = base64.b64encode(digest.finalize()).decode()
    return document_handle
