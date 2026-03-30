from flask import Flask, request
import json
import os
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_public_key,
    load_pem_private_key,
)
from cryptography.hazmat.primitives import hashes
import signal
from repository_auxiliary_functions import *
from datetime import datetime, timedelta
from utils import *


app = Flask(__name__)

rep_keys()
state = load_state()


# Graceful shutdown handler
def shutdown_handler(signum, frame):
    print("Shutting down... Saving state.")
    save_state(state)
    os._exit(0)


# Register signal handlers
signal.signal(signal.SIGINT, shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


# <--- Anonymous API Routes --->
@app.route("/pub_key", methods=["GET"])
def pub_key():
    # Read repository public key
    with open("rep_pub_key.pem", "rb") as pkey_file:
        pem_data = pkey_file.read()
    return pem_data, 200, {"Content-Type": "application/x-pem-file"}


@app.route("/organization/create", methods=["POST"])
def org_create():
    data = request.get_json()
    if not data or "name" not in data or "owner" not in data:
        return json.dumps({"error": "Invalid payload"}), 400

    name = data["name"]
    owner = data["owner"]
    username = owner["username"]
    full_name = owner["full_name"]
    email = owner["email"]
    public_key = owner["public_key"]

    # Check if the organization already exists
    if name in state["organizations"]:
        return json.dumps({"error": "Organization name already exists"}), 400

    # Add the new organization to the repository
    state["organizations"][name] = {
        "owner": {
            username: {
                "full_name": full_name,
                "email": email,
                "public_key": public_key,
            }
        },
        "subjects": {
            username: {
                "full_name": full_name,
                "email": email,
                "public_key": public_key,
                "status": "active",
                "roles": ["manager"],
            }
        },
        "acl": {
            "manager": {
                "permissions": [
                    "role_acl",
                    "subject_new",
                    "subject_down",
                    "subject_up",
                    "doc_new",
                    "role_new",
                    "role_down",
                    "role_up",
                    "role_mod",
                ],
                "status": "active",
            }
        },
        "session_ids": [],
        "document_handles": [],
    }

    return json.dumps({"message": "Organization created"}), 201


# TO-DO: Change to send both the organization name and the owner name.
@app.route("/organization/list")
def org_list():
    payload = {}
    try:
        organizations = state["organizations"]
        for name in organizations:
            payload[name] = next(iter(organizations[name]["owner"]))
        return json.dumps(payload), 200
    except Exception as e:
        print(f"error: {e}")
        return json.dumps({"error": e}), 500


@app.route("/session/create", methods=["POST"])
def org_new_session():
    # Unpack received data
    data = request.get_json()
    received_encrypted_base_payload = base64.b64decode(data["encrypted_base_payload"])
    received_encrypted_key = base64.b64decode(data["encrypted_key"])
    received_hmac = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])
    received_signature = base64.b64decode(data["signature"])

    # First we need to decrypt the received key.
    # Since it's encrypted with the server public key we
    # need to decrypt with the server private key
    try:
        with open("rep_priv_key.pem", "rb") as pkey_file:
            rep_priv_key = load_pem_private_key(
                pkey_file.read(),
                password=os.environ.get("PASSWORD", "password1234").encode(),
            )
        decrypted_key = rep_priv_key.decrypt(
            received_encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as e:
        return json.dumps({"error": e}), 500

    # Divide the decrypted key into 2 parts (like it's done on the client side)
    new_encryption_key = decrypted_key[0:16]
    new_integrity_key = decrypted_key[16:]

    # Use the first part to decrypt the base payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(
            received_encrypted_base_payload, new_encryption_key, received_iv
        )
    )

    # Check if the organization name, username and public key exist.
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    public_key = decrypted_payload["public_key"]
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400
    elif username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "User doesn't exist"}), 400
    elif (
        public_key
        != state["organizations"][organization_name]["subjects"][username]["public_key"]
    ):
        return json.dumps({"error": "Public key not compatible"}), 400

    # Verify the signature with the client public key (checks authenticity)
    rsa_public_key = load_pem_public_key(base64.b64decode(public_key))
    try:
        rsa_public_key.verify(
            received_signature,
            received_encrypted_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        return json.dumps({"error": f"Signature verification failed: {str(e)}"}), 400

    # Verify HMAC (checks integrity)
    calculated_hmac_signature = calculate_hmac(
        received_encrypted_key, new_integrity_key
    )
    if calculated_hmac_signature != received_hmac:
        return json.dumps({"error": "HMAC not the same."}), 400

    # Create session information
    # Session ID
    session_id = str(os.urandom(16))
    while session_id in state["sessions"]:
        session_id = str(os.urandom(16))

    # Expiration Time
    current_time = datetime.now()
    expiration_time = current_time + timedelta(hours=1)
    expiration_time = expiration_time.strftime("%d-%m-%Y %H:%M:%S")

    # Save session data on the server side
    state["sessions"][session_id] = {
        "subject": username,
        "organization": organization_name,
        "roles": [],
        "keys": {
            "encryption_key": base64.b64encode(new_encryption_key).decode(),
            "integrity_key": base64.b64encode(new_integrity_key).decode(),
            "nonce": base64.b64encode(received_nonce).decode(),
        },
        "expiration_TIME": expiration_time,
    }

    state["organizations"][organization_name]["session_ids"].append(session_id)

    # Send the session ID and expiration time to the client
    return (
        json.dumps({"session_id": session_id, "expiration_time": expiration_time}),
        200,
    )


@app.route("/doc/get/file_by_handle", methods=["POST"])
def get_doc_content_by_handle():
    # Unpack data
    data = request.get_json()
    file_handle = data["file_handle"]

    # Search for asked file
    file_path = f"docs/{file_handle}"
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            return (
                json.dumps(
                    {"encrypted_file_content": base64.b64encode(f.read()).decode()}
                ),
                200,
            )
    else:
        return json.dumps({"error": "File handle doesn't exist"}), 400


# <-------------------------------->


# <--- Authenticated API Routes --->
# rep_assume_role
@app.route("/role/assume", methods=["POST"])
def role_assume():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    role_to_assume = decrypted_payload["role"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o role existe dentro da organização
    if role_to_assume not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    # Verificar se o subject tem permissão para assumir a role
    if (
        role_to_assume
        not in state["organizations"][organization_name]["subjects"][username]["roles"]
    ):
        return (
            json.dumps(
                {
                    "error": "Cannot assume role because subject doesn't have the right to this role"
                }
            ),
            400,
        )

    # Adicionar essa role ao subject nessa session, caso ele não o tenha ainda
    if role_to_assume not in state["sessions"][received_session_id]["roles"]:
        state["sessions"][received_session_id]["roles"].append(role_to_assume)
        return json.dumps({"status": "success", "message": "Role assumed"}), 200

    return json.dumps({"error": "Already have that role."}), 400


# rep_drop_role
@app.route("/role/drop", methods=["POST"])
def role_drop():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    role_to_drop = decrypted_payload["role"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    if role_to_drop not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    # Pegar as roles atuais do subject na sua sessão
    subject_roles = [roles for roles in state["sessions"][received_session_id]["roles"]]

    # Verificar se o subject tem essa role
    if role_to_drop not in subject_roles:
        return (
            json.dumps(
                {"error": "Cannot drop role because subject doesn't have this role"}
            ),
            400,
        )

    # Remover a role do subject nessa session
    state["sessions"][received_session_id]["roles"].remove(role_to_drop)

    return json.dumps({"status": "success", "message": "Role dropped"}), 200


# rep_list_roles e rep_list_subject_roles
@app.route("/role/list", methods=["POST"])
def role_list():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    filter_username = decrypted_payload["filter_username"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    roles_and_status = {}
    # Se não houver username de filtro, devolver todos os roles da session e o seu status na organização
    if not filter_username:
        for role in state["sessions"][received_session_id]["roles"]:
            roles_and_status[role] = state["organizations"][organization_name]["acl"][
                role
            ]["status"]
        return json.dumps(roles_and_status), 200
    # Se houver username de filtro
    else:
        # Verificar se o username de filtro existe
        if filter_username in state["organizations"][organization_name]["subjects"]:
            # Procurar as roles do filter_username
            for role in state["organizations"][organization_name]["subjects"][
                filter_username
            ]["roles"]:
                roles_and_status[role] = state["organizations"][organization_name][
                    "acl"
                ][role]["status"]
            return json.dumps(roles_and_status), 200

        return json.dumps({"error": "Username doesn't exist"}), 400


# rep_list_subjects
@app.route("/subject/list", methods=["POST"])
def org_list_subjects():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    filter_username = decrypted_payload["filter_username"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Se o username usado para filter não existir na organização, returnar erro
    elif (
        filter_username
        and filter_username not in state["organizations"][organization_name]["subjects"]
    ):
        return json.dumps({"error": "Username used for filter doesn't exist"}), 400

    # Filtrar os users, se necessário, e devolver ao cliente a lista
    if (
        filter_username
        and filter_username in state["organizations"][organization_name]["subjects"]
    ):
        subject_status = state["organizations"][organization_name]["subjects"][
            filter_username
        ]["status"]
        return json.dumps({filter_username: subject_status}), 200

    # Se não for dado um username como filtro, devolver todos os usernames e status de todos os
    # subjects da organização
    elif not filter_username:
        usernames_and_status = {}
        for subject_username in state["organizations"][organization_name]["subjects"]:
            usernames_and_status[subject_username] = state["organizations"][
                organization_name
            ]["subjects"][subject_username]["status"]
        return json.dumps(usernames_and_status), 200


# rep_list_role_subjects
@app.route("/role/list/subjects", methods=["POST"])
def role_list_subject():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    filter_role = decrypted_payload["filter_role"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o role a filtrar os subjects existe
    if filter_role not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    subjects_list = [
        subject
        for subject in state["organizations"][organization_name]["subjects"]
        if filter_role
        in state["organizations"][organization_name]["subjects"][subject]["roles"]
    ]

    return json.dumps(subjects_list), 200


# rep_list_role_permissions
@app.route("/role/list/permissions", methods=["POST"])
def role_list_permissions():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    filter_role = decrypted_payload["filter_role"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o role a filtrar os subjects existe
    if filter_role not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    role_permissions = state["organizations"][organization_name]["acl"][filter_role][
        "permissions"
    ]

    return json.dumps(role_permissions), 200


# rep_list_permission_roles
@app.route("/permission/list/role", methods=["POST"])
def permission_list_roles():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    filter_permission = decrypted_payload["filter_permission"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se a permissão a filtrar é uma permissão da organização ou dos documentos
    if (
        filter_permission
        in state["organizations"][organization_name]["acl"]["manager"]["permissions"]
    ):
        roles = [
            role
            for role in state["organizations"][organization_name]["acl"]
            if filter_permission
            in state["organizations"][organization_name]["acl"][role]["permissions"]
        ]
        return json.dumps({"type": "Organization roles", "roles": roles}), 200

    elif filter_permission in ["DOC_acl", "DOC_READ", "DOC_DELETE"]:
        docs_and_roles = {}
        for document_handle in state["organizations"][organization_name][
            "document_handles"
        ]:
            for role in state["documents"][document_handle]["acl"]:
                if (
                    filter_permission
                    in state["documents"][document_handle]["acl"][role]
                ):
                    if (
                        state["documents"][document_handle]["NAME"]
                        not in docs_and_roles
                    ):
                        docs_and_roles[state["documents"][document_handle]["NAME"]] = [
                            role
                        ]
                    else:
                        docs_and_roles[
                            state["documents"][document_handle]["NAME"]
                        ].append(role)

        return json.dumps({"type": "documents roles", "roles": docs_and_roles}), 200

    else:
        return json.dumps({"error": "Permission doesn't exist"}), 400


# rep_list_docs
@app.route("/doc/list", methods=["POST"])
def org_list_docs():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    filter_username = decrypted_payload["filter_username"]
    filter_date_relation = decrypted_payload["filter_date_relation"]
    filter_date = decrypted_payload["filter_date"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Se não houver filtro de username ou data, enviar todos os docs
    if not any([filter_username, filter_date_relation, filter_date]):
        document_handles = state["organizations"][organization_name]["document_handles"]
        documents_list = [
            (
                state["documents"][document_handle]["NAME"],
                state["documents"][document_handle]["CREATOR"],
                state["documents"][document_handle]["CREATION_DATE"],
            )
            for document_handle in document_handles
        ]
        return json.dumps({"documents": documents_list}), 200

    # Se houver username mas não data
    elif filter_username and not all([filter_date_relation, filter_date]):
        document_handles = state["organizations"][organization_name]["document_handles"]
        documents_list = [
            (
                state["documents"][document_handle]["NAME"],
                state["documents"][document_handle]["CREATOR"],
                state["documents"][document_handle]["CREATION_DATE"],
            )
            for document_handle in document_handles
            if state["documents"][document_handle]["CREATOR"] == filter_username
        ]
        return json.dumps({"documents": documents_list}), 200

    # Se houver data mas não username
    elif not filter_username and all([filter_date_relation, filter_date]):
        document_handles = state["organizations"][organization_name]["document_handles"]
        if filter_date_relation == "nt":
            documents_list = [
                (
                    state["documents"][document_handle]["NAME"],
                    state["documents"][document_handle]["CREATOR"],
                    state["documents"][document_handle]["CREATION_DATE"],
                )
                for document_handle in document_handles
                if state["documents"][document_handle]["CREATION_DATE"] > filter_date
            ]
            return json.dumps({"documents": documents_list}), 200

        elif filter_date_relation == "ot":
            documents_list = [
                (
                    state["documents"][document_handle]["NAME"],
                    state["documents"][document_handle]["CREATOR"],
                    state["documents"][document_handle]["CREATION_DATE"],
                )
                for document_handle in document_handles
                if state["documents"][document_handle]["CREATION_DATE"] < filter_date
            ]
            return json.dumps({"documents": documents_list}), 200

        elif filter_date_relation == "et":
            documents_list = [
                (
                    state["documents"][document_handle]["NAME"],
                    state["documents"][document_handle]["CREATOR"],
                    state["documents"][document_handle]["CREATION_DATE"],
                )
                for document_handle in document_handles
                if state["documents"][document_handle]["CREATION_DATE"] == filter_date
            ]
            return json.dumps({"documents": documents_list}), 200

        else:
            return (
                json.dumps(
                    {"error": "Date relation filter not valid. Must be: [nt/ot/et]"}
                ),
                400,
            )

    # Se for dado todos os argumentos
    else:
        document_handles = state["organizations"][organization_name]["document_handles"]
        if filter_date_relation == "nt":
            documents_list = [
                (
                    state["documents"][document_handle]["NAME"],
                    state["documents"][document_handle]["CREATOR"],
                    state["documents"][document_handle]["CREATION_DATE"],
                )
                for document_handle in document_handles
                if (
                    state["documents"][document_handle]["CREATOR"] == filter_username
                    and state["documents"][document_handle]["CREATION_DATE"]
                    > filter_date
                )
            ]
            return json.dumps({"documents": documents_list}), 200

        elif filter_date_relation == "ot":
            documents_list = [
                (
                    state["documents"][document_handle]["NAME"],
                    state["documents"][document_handle]["CREATOR"],
                    state["documents"][document_handle]["CREATION_DATE"],
                )
                for document_handle in document_handles
                if (
                    state["documents"][document_handle]["CREATOR"] == filter_username
                    and state["documents"][document_handle]["CREATION_DATE"]
                    < filter_date
                )
            ]
            return json.dumps({"documents": documents_list}), 200

        elif filter_date_relation == "et":
            documents_list = [
                (
                    state["documents"][document_handle]["NAME"],
                    state["documents"][document_handle]["CREATOR"],
                    state["documents"][document_handle]["CREATION_DATE"],
                )
                for document_handle in document_handles
                if (
                    state["documents"][document_handle]["CREATOR"] == filter_username
                    and state["documents"][document_handle]["CREATION_DATE"]
                    == filter_date
                )
            ]
            return json.dumps({"documents": documents_list}), 200

        else:
            return (
                json.dumps(
                    {"error": "Date relation filter not valid. Must be: [nt/ot/et]"}
                ),
                400,
            )


# <-------------------------------->


# <--- Authorized API Routes --->
@app.route("/subject/create", methods=["POST"])
def org_new_subject():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    new_subject = decrypted_payload["new_subject"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o username não existe já
    if new_subject[0] in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username already exist"}), 400

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se essa role tem a permissão
    for role in active_subject_roles:
        if (
            "subject_new"
            in state["organizations"][organization_name]["acl"][role]["permissions"]
        ):

            # Adicionar o novo subject
            state["organizations"][organization_name]["subjects"][new_subject[0]] = {
                "full_name": new_subject[1],
                "email": new_subject[2],
                "public_key": new_subject[3],
                "status": "active",
                "roles": [],
            }

            return json.dumps({"Success": "Subject added"}), 200

    return json.dumps({"error": "You don't have the necessary permission"}), 400


@app.route("/subjects/suspend", methods=["POST"])
def org_suspend_subject():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    subject_to_suspend = decrypted_payload["subject_to_suspend"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o subject a mudar o status existe
    if subject_to_suspend not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Subject to change doesn't exist"}), 400

    # Se o subject a ser suspenso for o unico com a role manager, este não pode ser suspenso
    if (
        "manager"
        in state["organizations"][organization_name]["subjects"][subject_to_suspend][
            "roles"
        ]
    ):
        owners = [
            subject
            for subject in state["organizations"][organization_name]["subjects"]
            if "manager"
            in state["organizations"][organization_name]["subjects"][subject]["roles"]
            and subject != subject_to_suspend
        ]
        if not owners:
            return (
                json.dumps(
                    {
                        "error": "Not possible to suspend subject. There must always be a manager in a organization."
                    }
                ),
                400,
            )

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se essa role tem a permissão
    for role in active_subject_roles:
        if (
            "subject_down"
            in state["organizations"][organization_name]["acl"][role]["permissions"]
        ):

            state["organizations"][organization_name]["subjects"][subject_to_suspend][
                "status"
            ] = "SUSPENDED"

            return json.dumps({"Success": "Subject status changed to suspended"}), 200

    return json.dumps({"error": "You don't have the necessary permission"}), 400


@app.route("/subjects/activate", methods=["POST"])
def org_activate_subject():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    subject_to_activate = decrypted_payload["subject_to_activate"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o subject a mudar o status existe
    if subject_to_activate not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Subject to change doesn't exist"}), 400

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se essa role tem a permissão
    for role in active_subject_roles:
        if (
            "subject_up"
            in state["organizations"][organization_name]["acl"][role]["permissions"]
        ):

            state["organizations"][organization_name]["subjects"][subject_to_activate][
                "status"
            ] = "active"

            return json.dumps({"Success": "Subject status changed to active"}), 200

    return json.dumps({"error": "You don't have the necessary permission"}), 400


@app.route("/role/add", methods=["POST"])
def role_add():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    new_role = decrypted_payload["role"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se essa role tem a permissão
    for role in active_subject_roles:
        if (
            "role_new"
            in state["organizations"][organization_name]["acl"][role]["permissions"]
        ):

            # Verificar se a role que está a ser adicionada já existe
            if new_role in state["organizations"][organization_name]["acl"]:
                return json.dumps({"error": "Role already exists."}), 400

            state["organizations"][organization_name]["acl"][new_role] = {
                "permissions": [],
                "status": "active",
            }

            return json.dumps({"status": "success", "message": "Role created"}), 200

    return json.dumps({"error": "Subject missing permissions to add role"}), 400


@app.route("/role/change/status", methods=["POST"])
def role_change_status():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    role = decrypted_payload["role"]
    operation = decrypted_payload["operation"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    if operation == "suspend":
        subject_active_roles = [
            role
            for role in state["sessions"][received_session_id]["roles"]
            if state["organizations"][organization_name]["acl"][role]["status"]
            == "active"
        ]
        for subject_role in subject_active_roles:
            if (
                "role_down"
                in state["organizations"][organization_name]["acl"][subject_role][
                    "permissions"
                ]
            ):
                state["organizations"][organization_name]["acl"][role][
                    "status"
                ] = "SUSPENDED"
                return (
                    json.dumps({"status": "success", "message": "Role suspended"}),
                    200,
                )
        return json.dumps({"error": "Missing role_down permission"}), 400

    elif operation == "reactivate":
        subject_active_roles = [
            role
            for role in state["sessions"][received_session_id]["roles"]
            if state["organizations"][organization_name]["acl"][role]["status"]
            == "active"
        ]
        for subject_role in subject_active_roles:
            if (
                "role_up"
                in state["organizations"][organization_name]["acl"][subject_role][
                    "permissions"
                ]
            ):
                state["organizations"][organization_name]["acl"][role][
                    "status"
                ] = "active"
                return (
                    json.dumps({"status": "success", "message": "Role reactivated"}),
                    200,
                )
        return json.dumps({"error": "Missing role_up permission"}), 400

    else:
        return json.dumps({"error": "Operation invalid"}), 400


@app.route("/role/add/permission", methods=["POST"])
def role_add_permission():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    role = decrypted_payload["role"]
    username_or_permission = decrypted_payload["username_or_permission"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o subject tem a permissão necessária
    active_subject_roles = [
        subject_role
        for subject_role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][subject_role]["status"]
        == "active"
    ]
    for subject_role in active_subject_roles:
        if (
            "role_mod"
            in state["organizations"][organization_name]["acl"][subject_role][
                "permissions"
            ]
        ):

            # Verificar se o argumento recebido é um username ou uma permissão
            if (
                username_or_permission
                in state["organizations"][organization_name]["acl"]["manager"][
                    "permissions"
                ]
            ):
                # Significa que é uma permissão
                new_permission = username_or_permission

                # Verificar se a role não tem a permissão já
                if (
                    new_permission
                    in state["organizations"][organization_name]["acl"][role][
                        "permissions"
                    ]
                ):
                    return json.dumps({"error": "Role already has permission"}), 400

                # Adicionar permissão
                state["organizations"][organization_name]["acl"][role][
                    "permissions"
                ].append(new_permission)
                return (
                    json.dumps(
                        {"status": "success", "message": "Permission added to role"}
                    ),
                    200,
                )

            elif (
                username_or_permission
                in state["organizations"][organization_name]["subjects"]
            ):
                # Significa que é um username
                username = username_or_permission

                # Verificar se o username não tem já a role
                if (
                    role
                    in state["organizations"][organization_name]["subjects"][username][
                        "roles"
                    ]
                ):
                    return json.dumps({"error": f"Subject already has the role"}), 400

                # Adicionar role ao subject
                state["organizations"][organization_name]["subjects"][username][
                    "roles"
                ].append(role)
                return (
                    json.dumps(
                        {"status": "success", "message": "Role added to subject"}
                    ),
                    200,
                )

            else:
                return (
                    json.dumps(
                        {
                            "error": "Last argument must be either a valid username or permission"
                        }
                    ),
                    400,
                )

    return json.dumps({"error": "You must have the right permissions"}), 400


@app.route("/role/remove/permission", methods=["POST"])
def role_remove_permission():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    role = decrypted_payload["role"]
    username_or_permission = decrypted_payload["username_or_permission"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verificar se o subject tem a permissão necessária
    active_subject_roles = [
        subject_role
        for subject_role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][subject_role]["status"]
        == "active"
    ]
    for subject_role in active_subject_roles:
        if (
            "role_mod"
            in state["organizations"][organization_name]["acl"][subject_role][
                "permissions"
            ]
        ):

            # Verificar se o argumento recebido é um username ou uma permissão
            if (
                username_or_permission
                in state["organizations"][organization_name]["acl"]["manager"][
                    "permissions"
                ]
            ):
                # Significa que é uma permissão
                new_permission = username_or_permission

                # Verificar se a role tem a permissão
                if (
                    new_permission
                    not in state["organizations"][organization_name]["acl"][role][
                        "permissions"
                    ]
                ):
                    return (
                        json.dumps({"error": "Role doesn't have that permission"}),
                        400,
                    )

                # Remover permissão
                state["organizations"][organization_name]["acl"][role][
                    "permissions"
                ].remove(new_permission)
                return (
                    json.dumps(
                        {"status": "success", "message": "Permission removed from role"}
                    ),
                    200,
                )

            elif (
                username_or_permission
                in state["organizations"][organization_name]["subjects"]
            ):
                # Significa que é um username
                username = username_or_permission

                # Verificar se o username tem a role
                if (
                    role
                    not in state["organizations"][organization_name]["subjects"][
                        username
                    ]["roles"]
                ):
                    return json.dumps({"error": "Subject doesn't have the role"}), 400

                # Retirar role do subject
                state["organizations"][organization_name]["subjects"][username][
                    "roles"
                ].remove(role)
                return (
                    json.dumps(
                        {"status": "success", "message": "Role removed from subject"}
                    ),
                    200,
                )

            else:
                return (
                    json.dumps(
                        {
                            "error": "Last argument must be either a valid username or permission"
                        }
                    ),
                    400,
                )

    return json.dumps({"error": "You must have the right permissions"}), 400


@app.route("/doc/create", methods=["POST"])
def doc_new():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_encrypted_document_content = base64.b64decode(
        data["encrypted_document_content"]
    )
    received_payload_iv = base64.b64decode(data["payload_iv"])
    received_nonce = base64.b64decode(data["nonce"])
    received_hmac_signature = base64.b64decode(data["hmac"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(
            received_encrypted_payload, encryption_key, received_payload_iv
        )
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode()
        + received_encrypted_document_content
        + payload_bytes
        + received_payload_iv
        + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    secret_key = base64.b64decode(decrypted_payload["secret_key"])
    document_iv = base64.b64decode(decrypted_payload["document_iv"])
    document_name = decrypted_payload["document_name"]
    file_handle = decrypted_payload["file_handle"]
    algorithm = decrypted_payload["algorithm"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se essa role tem a permissão
    for role in active_subject_roles:
        if (
            "doc_new"
            in state["organizations"][organization_name]["acl"][role]["permissions"]
        ):

            # Ler a chave do repositório
            with open("rep_pub_key.pem", "rb") as pkey_file:
                rep_pub_key = load_pem_public_key(pkey_file.read())

            # Encriptar a chave secreta com a pública do server
            encrypted_key = rep_pub_key.encrypt(
                secret_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Encriptar a informação do algoritmo com a pública do server
            encrypted_alg = rep_pub_key.encrypt(
                algorithm.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Criar o document_handle: hash do nome do documento + nome da organização
            digest = hashes.Hash(hashes.SHA256())
            message = document_name.encode() + organization_name.encode()
            digest.update(message)
            document_handle = digest.finalize()

            # Verificar se o document_handle é válido (ou seja, se o document_name já existe na organization)
            if base64.b64encode(document_handle).decode() in state["documents"]:
                return (
                    json.dumps(
                        {"error": "Document name already exists in the organization"}
                    ),
                    400,
                )

            # Adicionar o diretório /docs caso não exista
            docs_dir_path = "/docs"
            if not os.path.exists(docs_dir_path):
                os.mkdir(docs_dir_path)

            file_handle = file_handle.replace("/", "_")
            file_path = f"{docs_dir_path}/{file_handle}"

            with open(file_path, "wb") as f:
                f.write(received_encrypted_document_content)

            # Definir o tempo de criação do documento
            current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            state["documents"][base64.b64encode(document_handle).decode()] = {
                "NAME": document_name,
                "CREATION_DATE": current_time,
                "CREATOR": username,
                "organization": organization_name,
                "FILE_HANDLE": file_handle,
                "acl": {"manager": ["DOC_ACL", "DOC_READ", "DOC_DELETE"]},
                "DELETER": None,
                "ALG": base64.b64encode(encrypted_alg).decode(),
                "KEY": base64.b64encode(encrypted_key).decode(),
                "IV": base64.b64encode(document_iv).decode(),
            }

            state["organizations"][organization_name]["document_handles"].append(
                base64.b64encode(document_handle).decode()
            )

            return json.dumps({"status": "success", "message": "Document added"}), 200

    return json.dumps({"error": "Missing permissions to add document"}), 400


@app.route("/doc/get/metadata", methods=["POST"])
def doc_get_doc_metadata():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_payload_iv = base64.b64decode(data["payload_iv"])
    received_nonce = base64.b64decode(data["nonce"])
    received_hmac_signature = base64.b64decode(data["hmac"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(
            received_encrypted_payload, encryption_key, received_payload_iv
        )
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode()
        + payload_bytes
        + received_payload_iv
        + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    document_name = decrypted_payload["document_name"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Criar o document_handle: hash do nome do documento + nome da organização
    digest = hashes.Hash(hashes.SHA256())
    message = document_name.encode() + organization_name.encode()
    digest.update(message)
    document_handle = base64.b64encode(digest.finalize()).decode()

    # Verificar se o document_handle é válido
    if document_handle not in state["documents"]:
        return json.dumps({"error": "Document doesn't exist"}), 400

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se tem a permissão necessária
    for role in active_subject_roles:
        if (
            role in state["documents"][document_handle]["acl"]
            and "DOC_READ" in state["documents"][document_handle]["acl"][role]
        ):

            # Ler a chave do repositório
            with open("rep_priv_key.pem", "rb") as pkey_file:
                rep_priv_key = load_pem_private_key(
                    pkey_file.read(),
                    password=os.environ.get("PASSWORD", "password1234").encode(),
                )

            # Descifrar o "ALG"
            decrypted_alg = rep_priv_key.decrypt(
                base64.b64decode(state["documents"][document_handle]["ALG"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Descifrar a "KEY"
            decrypted_key = rep_priv_key.decrypt(
                base64.b64decode(state["documents"][document_handle]["KEY"]),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            # Preparar o payload com os metadados do documento
            payload = {
                "document_name": state["documents"][document_handle]["NAME"],
                "creation_date": state["documents"][document_handle]["CREATION_DATE"],
                "creator": state["documents"][document_handle]["CREATOR"],
                "organization_name": state["documents"][document_handle][
                    "organization"
                ],
                "file_handle": state["documents"][document_handle]["FILE_HANDLE"],
                "acl": state["documents"][document_handle]["acl"],
                "deleter": state["documents"][document_handle]["DELETER"],
                "algorithm": base64.b64encode(decrypted_alg).decode(),
                "key": base64.b64encode(decrypted_key).decode(),
                "iv": state["documents"][document_handle]["IV"],
            }

            # Encriptar o payload com os metadados com a chave de sessão
            payload_bytes = json.dumps(payload).encode()
            encrypted_payload, payload_iv = encrypt_data_AES_CBC(
                payload_bytes, encryption_key
            )

            # Gerar um nonce
            nonce = os.urandom(16)
            while (
                base64.b64encode(nonce).decode()
                in state["sessions"][received_session_id]["keys"]["nonce"]
            ):
                nonce = os.urandom(16)

            # Gerar o hmac
            message = payload_bytes + payload_iv + nonce
            hmac_signature = calculate_hmac(message, integrity_key)

            # Possivelmente adicionar uma assinatura digital para segurança extra

            # Preparar o payload final e enviar
            final_payload = {
                "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
                "payload_iv": base64.b64encode(payload_iv).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "hmac": base64.b64encode(hmac_signature).decode(),
            }

            return json.dumps(final_payload), 200

    return json.dumps({"error": "Missing permissions to read document metadata"}), 400


@app.route("/doc/clear/file-handle", methods=["POST"])
def doc_clear_file_handle():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    document_name = decrypted_payload["document_name"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Criar o document_handle: hash do nome do documento + nome da organização
    digest = hashes.Hash(hashes.SHA256())
    message = document_name.encode() + organization_name.encode()
    digest.update(message)
    document_handle = base64.b64encode(digest.finalize()).decode()

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se tem a permissão necessária
    for role in active_subject_roles:
        if (
            role in state["documents"][document_handle]["acl"]
            and "DOC_DELETE" in state["documents"][document_handle]["acl"][role]
        ):

            # Verificar se o document_handle é válido (ou seja, se o document_name existe na organization)
            if document_handle not in state["documents"]:
                return (
                    json.dumps(
                        {"error": "Document name doesn't exists in the organization"}
                    ),
                    400,
                )

            # Limpar o file_handle
            state["documents"][document_handle]["FILE_HANDLE"] = None

            return json.dumps({"status": "success", "message": "Document deleted"}), 200

    return json.dumps({"error": "Missing permissions to delete file handle"}), 400


@app.route("/doc/change/acl", methods=["POST"])
def doc_change_acl():
    data = request.get_json()
    received_session_id = data["session_id"]
    received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
    received_hmac_signature = base64.b64decode(data["hmac"])
    received_nonce = base64.b64decode(data["nonce"])
    received_iv = base64.b64decode(data["iv"])

    # Verificar se o session ID é valido
    if received_session_id not in state["sessions"]:
        return json.dumps({"error": "Session ID not valid"}), 400

    # Verificar se a sessão está dentro do tempo válido
    current_time = datetime.now()
    expiration_time = datetime.strptime(
        state["sessions"][received_session_id]["expiration_TIME"], "%d-%m-%Y %H:%M:%S"
    )
    if current_time > expiration_time:
        state["sessions"].pop(received_session_id)
        return (
            json.dumps(
                {"error": "Session expiration time reached. Create a new session."}
            ),
            400,
        )

    # Verificar se o nonce é válido
    correct_nonce = calculate_next_nonce(
        base64.b64decode(state["sessions"][received_session_id]["keys"]["nonce"])
    )
    if received_nonce != correct_nonce:
        return json.dumps({"error": "Nonce not valid"}), 400
    state["sessions"][received_session_id]["keys"]["nonce"] = base64.b64encode(
        received_nonce
    ).decode()

    # Obter as chaves da sessão
    encryption_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["encryption_key"]
    )
    integrity_key = base64.b64decode(
        state["sessions"][received_session_id]["keys"]["integrity_key"]
    )

    # Desencriptar o payload
    decrypted_payload = json.loads(
        decrypt_data_AES_CBC(received_encrypted_payload, encryption_key, received_iv)
    )

    # Serializar o payload e verificar se o HMAC é valido
    payload_bytes = json.dumps(decrypted_payload).encode()
    message = (
        received_session_id.encode() + payload_bytes + received_iv + received_nonce
    )
    calculated_hmac_signature = calculate_hmac(message, integrity_key)

    if calculated_hmac_signature != received_hmac_signature:
        return json.dumps({"error": "HMAC not valid"}), 400

    # Obter os dados do payload
    organization_name = decrypted_payload["organization_name"]
    username = decrypted_payload["username"]
    document_name = decrypted_payload["document_name"]
    operation = decrypted_payload["operation"]
    role_to_modify = decrypted_payload["role"]
    permission = decrypted_payload["permission"]

    # Verificar se a organização existe
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verificar se o username é válido
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Criar o document_handle: hash do nome do documento + nome da organização
    digest = hashes.Hash(hashes.SHA256())
    message = document_name.encode() + organization_name.encode()
    digest.update(message)
    document_handle = base64.b64encode(digest.finalize()).decode()

    # Verificar se o document_handle é válido (ou seja, se o document_name existe na organization)
    if document_handle not in state["documents"]:
        return (
            json.dumps({"error": "Document name doesn't exists in the organization"}),
            400,
        )

    # Filtrar apenas as roles que estão ativas
    active_subject_roles = [
        role
        for role in state["sessions"][received_session_id]["roles"]
        if state["organizations"][organization_name]["acl"][role]["status"] == "active"
    ]

    # Verificar se tem a permissão necessária
    for role in active_subject_roles:
        if (
            role in state["documents"][document_handle]["acl"]
            and "DOC_acl" in state["documents"][document_handle]["ACL"][role]
        ):

            # Verificar se a operação que quer realizar é valida
            if operation != "+" and operation != "-":
                return json.dumps({"error": "Invalid operation"})

            # Verificar se a permissão que o subject quer adicionar existe
            if permission not in ["DOC_acl", "DOC_READ", "DOC_DELETE"]:
                return json.dumps({"error": "Permission does not exist"})

            # Verificar se a role que o subject está a tentar alterar na acl do documento existe
            if role_to_modify not in state["organizations"][organization_name]["acl"]:
                return json.dumps(
                    {"error": "Role to modify does not exist in this organization"}
                )

            # Verificar se a entry para essa role já existe na acl do documento
            # Se não existir, criar
            if role_to_modify in state["documents"][document_handle]["acl"]:
                if operation == "+":
                    state["documents"][document_handle]["acl"][role_to_modify].append(
                        permission
                    )
                elif (
                    operation == "-"
                    and permission
                    in state["documents"][document_handle]["acl"][role_to_modify]
                ):
                    state["documents"][document_handle]["acl"][role_to_modify].remove(
                        permission
                    )

                # No caso em que o subject está a tentar remover a permissão de uma role que não tem essa permissão
                else:
                    return json.dumps(
                        {
                            "error": "Role to change does not have this permission in this document"
                        }
                    )
            else:
                if operation == "+":
                    state["documents"][document_handle]["acl"][role_to_modify] = [
                        permission
                    ]
                # No caso em que o subject está a tentar remover a permissão de uma role que não tem permissões
                elif operation == "-":
                    return json.dumps(
                        {
                            "error": "Role to change does not have this permission in this document"
                        }
                    )

            return (
                json.dumps(
                    {
                        "status": "success",
                        "message": "Document acl updated successfully",
                    }
                ),
                200,
            )

    return json.dumps({"error": "Missing permissions to change document acl"}), 400


# <----------------------------->


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
