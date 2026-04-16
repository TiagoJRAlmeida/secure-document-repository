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
from datetime import datetime, timedelta
from crypto_utils import *
from utils import *

import logging

logging.basicConfig(format="  [%(levelname)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)
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
    if not data or "organization" not in data or "owner" not in data:
        return json.dumps({"error": "Invalid payload"}), 400

    organization_name = data["organization"]
    owner = data["owner"]
    username = owner["username"]
    name = owner["name"]
    email = owner["email"]
    public_key = owner["public_key"]

    # Check if the organization already exists
    if organization_name in state["organizations"]:
        return json.dumps({"error": "Organization name already exists"}), 400

    # Add the new organization to the repository
    state["organizations"][organization_name] = {
        "owner": {
            username: {
                "name": name,
                "email": email,
                "public_key": public_key,
            }
        },
        "subjects": {
            username: {
                "name": name,
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

    return json.dumps({"message": "Organization created"}), 200


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
    encrypted_base_payload = base64.b64decode(data["encrypted_base_payload"])
    encrypted_key = base64.b64decode(data["encrypted_key"])
    hmac = base64.b64decode(data["hmac"])
    nonce = base64.b64decode(data["nonce"])
    iv = base64.b64decode(data["iv"])
    signature = base64.b64decode(data["signature"])

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
            encrypted_key,
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
        decrypt_data_AES_CBC(encrypted_base_payload, new_encryption_key, iv)
    )

    # Check if the organization name, username and public key exist.
    organization_name = decrypted_payload["organization"]
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
            signature,
            encrypted_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        return json.dumps({"error": f"Signature verification failed: {str(e)}"}), 400

    # Verify HMAC (checks integrity)
    calculated_hmac = calculate_hmac(encrypted_key, new_integrity_key)
    if calculated_hmac != hmac:
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
            "nonce": base64.b64encode(nonce).decode(),
        },
        "expiration_time": expiration_time,
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

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    role_to_assume = decrypted_payload["role"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if role exists inside organization
    if role_to_assume not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    # Verify if user has permissions to assume role
    subject_roles = state["organizations"][organization_name]["subjects"][username][
        "roles"
    ]
    if role_to_assume not in subject_roles:
        return (
            json.dumps({"error": "Subject doesn't have the right to this role"}),
            400,
        )

    # Add role to subject session
    session_id = data["session_id"]
    state["sessions"][session_id]["roles"].append(role_to_assume)
    return json.dumps({"message": "Role assumed"}), 200


# rep_drop_role
@app.route("/role/drop", methods=["POST"])
def role_drop():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    role_to_drop = decrypted_payload["role"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if role exists inside organization
    if role_to_drop not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    # Verify if subject has the role he wants to drop in the current session
    session_id = data["session_id"]
    subject_roles = state["sessions"][session_id]["roles"]
    if role_to_drop in subject_roles:
        state["sessions"][session_id]["roles"].remove(role_to_drop)
        return json.dumps({"message": "Role dropped"}), 200
    else:
        return (
            json.dumps({"error": "Subject doesn't have this role"}),
            400,
        )


# rep_list_roles and rep_list_subject_roles
@app.route("/role/list", methods=["POST"])
def role_list():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    filter_username = decrypted_payload["filter_username"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # If no filter has been passed, return all session roles and their status
    roles_and_status = {}
    session_id = data["session_id"]
    organization = state["organizations"][organization_name]
    # rep_list_roles
    if not filter_username:
        for role in state["sessions"][session_id]["roles"]:
            roles_and_status[role] = organization["acl"][role]["status"]
        return json.dumps(roles_and_status), 200
    # Otherwise, verify if the filtered user exists and return it's roles
    # rep_list_subject_roles
    else:
        if filter_username in state["organizations"][organization_name]["subjects"]:
            subject_roles = organization["subjects"][filter_username]["roles"]
            for role in subject_roles:
                roles_and_status[role] = organization["acl"][role]["status"]
            return json.dumps(roles_and_status), 200
        else:
            return json.dumps({"error": "Username doesn't exist"}), 400


# rep_list_subjects
@app.route("/subject/list", methods=["POST"])
def org_list_subjects():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    filter_username = decrypted_payload["filter_username"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # If filter user is used, verify if he exists in the organization
    # And return it's status
    organization = state["organizations"][organization_name]
    if filter_username:
        if filter_username in organization["subjects"]:
            subject_status = organization["subjects"][filter_username]["status"]
            return json.dumps({filter_username: subject_status}), 200
        else:
            return json.dumps({"error": "Username used for filter doesn't exist"}), 400
    # If not filter user is passed, return every user and their status
    # inside the organization
    elif not filter_username:
        users_status = {}
        for username in organization["subjects"]:
            users_status[username] = organization["subjects"][username]["status"]
        return json.dumps(users_status), 200


# rep_list_role_subjects
@app.route("/role/list/subjects", methods=["POST"])
def role_list_subject():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    filter_role = decrypted_payload["filter_role"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if filter role exists
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

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    filter_role = decrypted_payload["filter_role"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if filter role exists
    if filter_role not in state["organizations"][organization_name]["acl"]:
        return json.dumps({"error": "Role doesn't exist"}), 400

    organization = state["organizations"][organization_name]
    role_permissions = organization["acl"][filter_role]["permissions"]
    return json.dumps(role_permissions), 200


# rep_list_permission_roles
@app.route("/permission/list/role", methods=["POST"])
def permission_list_roles():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    filter_permission = decrypted_payload["filter_permission"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if filter permission refers to an organization or document
    organization = state["organizations"][organization_name]
    if filter_permission in organization["acl"]["manager"]["permissions"]:
        roles = [
            role
            for role in organization["acl"]
            if filter_permission in organization["acl"][role]["permissions"]
        ]
        return json.dumps({"type": "Organization roles", "roles": roles}), 200
    elif filter_permission in ["doc_acl", "doc_read", "doc_delete"]:
        docs_and_roles = {}
        for document_handle in organization["document_handles"]:
            document = state["documents"][document_handle]
            for role in document["acl"]:
                if filter_permission in document["acl"][role]:
                    if document["name"] not in docs_and_roles:
                        docs_and_roles[document["name"]] = [role]
                    else:
                        docs_and_roles[document["name"]].append(role)
        return json.dumps({"type": "documents roles", "roles": docs_and_roles}), 200
    else:
        return json.dumps({"error": "Permission doesn't exist"}), 400


# rep_list_docs
@app.route("/doc/list", methods=["POST"])
def org_list_docs():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    filter_user = decrypted_payload["filter_username"]
    date_relation = decrypted_payload["filter_date_relation"]
    date = decrypted_payload["filter_date"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    document_handles = state["organizations"][organization_name]["document_handles"]
    documents_list = []
    # If no filters were passed, send every document
    if not any([filter_user, date_relation, date]):
        for handle in document_handles:
            document = state["documents"][handle]
            documents_list.append(
                (
                    document["name"],
                    document["creator"],
                    document["creation_date"],
                )
            )
    # If there is username filter but not for dates
    elif filter_user and not all([date_relation, date]):
        for handle in document_handles:
            document = state["documents"][handle]
            response = filter_doc_by_user(document, filter_user)
            if response["success"]:
                documents_list.append(response["success"])
    # If there is a date filter but not username filter
    elif not filter_user and all([date_relation, date]):
        for handle in document_handles:
            document = state["documents"][handle]
            response = filter_doc_by_date(document, date, date_relation)
            if "error" in response:
                return json.dumps(response), 400
            if response["success"]:
                documents_list.append(response["success"])
    # If both date and user filters are given
    else:
        for handle in document_handles:
            document = state["documents"][handle]
            response_date = filter_doc_by_date(document, date, date_relation)
            if "error" in response_date:
                return json.dumps(response_date), 400
            response_user = filter_doc_by_user(document, filter_user)
            if all((response_user["success"], response_date["success"])):
                documents_list.append(response_user["success"])
    return json.dumps({"documents": documents_list}), 200


# <-------------------------------->


# <--- Authorized API Routes --->
@app.route("/subject/create", methods=["POST"])
def org_new_subject():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    new_subject = decrypted_payload["new_subject"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if username is already taken
    if new_subject["username"] in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username already exist"}), 400

    # Get client roles (only active ones are considered)
    session_id = data["session_id"]
    organization = state["organizations"][organization_name]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and ddd new subject
    if has_permission(
        user_roles=user_roles, organization=organization, permission="subject_new"
    ):
        organization["subjects"][new_subject["username"]] = {
            "organization": new_subject["name"],
            "email": new_subject["email"],
            "public_key": new_subject["public_key"],
            "status": "active",
            "roles": [],
        }
        return (
            json.dumps({"success": f"Subject {new_subject["username"]} added"}),
            200,
        )
    else:
        return json.dumps({"error": "You don't have the necessary permission"}), 400


@app.route("/subjects/suspend", methods=["POST"])
def org_suspend_subject():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    subject_to_suspend = decrypted_payload["subject_to_suspend"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if target user exists
    if subject_to_suspend not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Subject to change doesn't exist"}), 400

    organization = state["organizations"][organization_name]
    # If target user is the only one with role manager, he can't be suspended
    if "manager" in organization["subjects"][subject_to_suspend]["roles"]:
        owners = [
            subject
            for subject in organization["subjects"]
            if "manager" in organization["subjects"][subject]["roles"]
            and subject != subject_to_suspend
        ]
        if not owners:
            return (
                json.dumps({"error": "Can't suspend the only manager."}),
                400,
            )

    # Get client roles (only active ones are considered)
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and suspend subject
    if has_permission(
        user_roles=user_roles, organization=organization, permission="subject_down"
    ):
        organization["subjects"][subject_to_suspend]["status"] = "suspended"
        return json.dumps({"success": "Subject status changed to suspended"}), 200
    else:
        return json.dumps({"error": "You don't have the necessary permission"}), 400


@app.route("/subjects/activate", methods=["POST"])
def org_activate_subject():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    subject_to_activate = decrypted_payload["subject_to_activate"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Verify if target user exists
    if subject_to_activate not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Subject to change doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and activate subject
    if has_permission(
        user_roles=user_roles, organization=organization, permission="subject_up"
    ):
        organization["subjects"][subject_to_activate]["status"] = "active"
        return json.dumps({"success": "Subject status changed to active"}), 200
    else:
        return json.dumps({"error": "You don't have the necessary permission"}), 400


@app.route("/role/add", methods=["POST"])
def role_add():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    new_role = decrypted_payload["role"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and add new role
    if has_permission(
        user_roles=user_roles, organization=organization, permission="role_new"
    ):
        organization["acl"][new_role] = {
            "permissions": [],
            "status": "active",
        }

        return json.dumps({"message": f"Role {new_role} created"}), 200
    else:
        return json.dumps({"error": "Subject missing permissions to add role"}), 400


@app.route("/role/change/status", methods=["POST"])
def role_change_status():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    role = decrypted_payload["role"]
    operation = decrypted_payload["operation"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    if operation == "suspend":
        # Verify client has correct permissions and suspend role
        if has_permission(
            user_roles=user_roles, organization=organization, permission="role_down"
        ):
            organization["acl"][role]["status"] = "suspended"
            return json.dumps({"message": "Role suspended"}), 200
        else:
            return json.dumps({"error": "Missing role_down permission"}), 400
    elif operation == "reactivate":
        # Verify client has correct permissions and activate role
        if has_permission(
            user_roles=user_roles, organization=organization, permission="role_up"
        ):
            organization["acl"][role]["status"] = "active"
            return json.dumps({"message": "Role reactivated"}), 200
        else:
            return json.dumps({"error": "Missing role_up permission"}), 400
    else:
        return json.dumps({"error": "Operation invalid"}), 400


@app.route("/role/add/permission", methods=["POST"])
def role_add_permission():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    role = decrypted_payload["role"]
    username_or_permission = decrypted_payload["username_or_permission"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]
    # Verify client has correct permissions and verify if recieved argument is
    # a username or permission
    if has_permission(
        user_roles=user_roles, organization=organization, permission="role_mod"
    ):
        # If it's a permission
        if username_or_permission in organization["acl"]["manager"]["permissions"]:
            new_permission = username_or_permission
            # Check if role already has permission
            if new_permission in organization["acl"][role]["permissions"]:
                return json.dumps({"error": "Role already has permission"}), 400
            else:
                organization["acl"][role]["permissions"].append(new_permission)
                return json.dumps({"message": "Permission added to role"}), 200
        # If it's a user
        elif username_or_permission in organization["subjects"]:
            username = username_or_permission
            # Check if user already has the role
            if role in organization["subjects"][username]["roles"]:
                return json.dumps({"error": "Subject already has the role"}), 400
            else:
                organization["subjects"][username]["roles"].append(role)
                return json.dumps({"message": "Role added to subject"}), 200
        else:
            return (
                json.dumps(
                    {
                        "error": "Last argument must be either a valid username or permission"
                    }
                ),
                400,
            )
    else:
        return json.dumps({"error": "You must have the role_mod permission"}), 400


@app.route("/role/remove/permission", methods=["POST"])
def role_remove_permission():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    role = decrypted_payload["role"]
    username_or_permission = decrypted_payload["username_or_permission"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and verify if recieved argument is
    # a username or permission
    if has_permission(
        user_roles=user_roles, organization=organization, permission="role_mod"
    ):
        # If it's a permission
        if username_or_permission in organization["acl"]["manager"]["permissions"]:
            new_permission = username_or_permission
            # Check if role has the permission
            if new_permission not in organization["acl"][role]["permissions"]:
                return json.dumps({"error": "Role doesn't have the permission"}), 400
            else:
                organization["acl"][role]["permissions"].remove(new_permission)
                return json.dumps({"message": "Permission remove from role"}), 200
        # If it's a user
        elif username_or_permission in organization["subjects"]:
            username = username_or_permission
            # Check if user has the role
            if role not in organization["subjects"][username]["roles"]:
                return json.dumps({"error": "Subject doesn't have the role"}), 400
            else:
                organization["subjects"][username]["roles"].remove(role)
                return json.dumps({"message": "Role remove from subject"}), 200
        else:
            return (
                json.dumps(
                    {
                        "error": "Last argument must be either a valid username or permission"
                    }
                ),
                400,
            )
    else:
        return json.dumps({"error": "You must have the role_mod permission"}), 400


@app.route("/doc/create", methods=["POST"])
def doc_new():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    logger.info(data["encrypted_document_content"])
    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    secret_key = base64.b64decode(decrypted_payload["secret_key"])
    document_iv = base64.b64decode(decrypted_payload["document_iv"])
    document_name = decrypted_payload["document_name"]
    file_handle = decrypted_payload["file_handle"]
    algorithm = decrypted_payload["algorithm"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and save doc
    if has_permission(
        user_roles=user_roles, organization=organization, permission="doc_new"
    ):
        # Load repository public key
        with open("rep_pub_key.pem", "rb") as pkey_file:
            rep_pub_key = load_pem_public_key(pkey_file.read())

        # Encrypt secret key used to encrypt the document with the rep public key
        encrypted_key = rep_pub_key.encrypt(
            secret_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Create document handle: hash(document name + organization name)
        document_handle = calculate_document_handle(document_name, organization_name)
        # Verify if document handle/name already exists in the organization
        if document_handle in state["documents"]:
            return (
                json.dumps(
                    {"error": "Document name already exists in the organization"}
                ),
                400,
            )

        # Create the directory /docs, if it doesn't exist already
        if not os.path.exists("docs"):
            os.mkdir("docs")

        file_handle = file_handle.replace("/", "_")
        file_path = f"docs/{file_handle}"
        encrypted_document_content = base64.b64decode(
            data["encrypted_document_content"]
        )
        with open(file_path, "wb") as f:
            f.write(encrypted_document_content)

        # Define creation time
        current_time = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        state["documents"][document_handle] = {
            "name": document_name,
            "creation_date": current_time,
            "creator": username,
            "organization": organization_name,
            "file_handle": file_handle,
            "acl": {"manager": ["doc_acl", "doc_read", "doc_delete"]},
            "deleter": None,
            "alg": algorithm,
            "key": base64.b64encode(encrypted_key).decode(),
            "iv": base64.b64encode(document_iv).decode(),
        }

        organization["document_handles"].append(document_handle)
        return json.dumps({"message": "Document added"}), 200
    else:
        return json.dumps({"error": "Missing permissions to add document"}), 400


@app.route("/doc/get/metadata", methods=["POST"])
def doc_get_doc_metadata():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    document_name = decrypted_payload["document_name"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Create document handle: hash(document name + organization name)
    document_handle = calculate_document_handle(document_name, organization_name)
    # Check if document_handle is valid
    if document_handle not in state["documents"]:
        return json.dumps({"error": "Document doesn't exist"}), 400
    else:
        document = state["documents"][document_handle]

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and save doc
    if has_permission(user_roles=user_roles, permission="doc_read", document=document):
        # Read repository private key and decrypt secret key
        with open("rep_priv_key.pem", "rb") as pkey_file:
            rep_priv_key = load_pem_private_key(
                pkey_file.read(),
                password=os.environ.get("PASSWORD", "password1234").encode(),
            )
        decrypted_key = rep_priv_key.decrypt(
            base64.b64decode(state["documents"][document_handle]["key"]),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Prepare payload with the document metadata
        document = state["documents"][document_handle]
        payload = {
            "document_name": document["name"],
            "creation_date": document["creation_date"],
            "creator": document["creator"],
            "organization": document["organization"],
            "file_handle": document["file_handle"],
            "acl": document["acl"],
            "deleter": document["deleter"],
            "algorithm": document["alg"],
            "key": base64.b64encode(decrypted_key).decode(),
            "iv": document["iv"],
        }
        # Load keys from session data
        session = state["sessions"][session_id]
        encryption_key = base64.b64decode(session["keys"]["encryption_key"])
        integrity_key = base64.b64decode(session["keys"]["integrity_key"])

        # Encrypt the payload
        payload_bytes = json.dumps(payload).encode()
        encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

        # Generate the new nonce
        nonce = os.urandom(16)
        nonce = base64.b64encode(nonce).decode()
        while nonce in session["keys"]["nonce"]:
            nonce = os.urandom(16)
            nonce = base64.b64encode(nonce).decode()

        # Generate the HMAC for integrity
        message = payload_bytes + iv + base64.b64decode(nonce)
        hmac = calculate_hmac(message, integrity_key)

        # Set final payload
        final_payload = {
            "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
            "payload_iv": base64.b64encode(iv).decode(),
            "nonce": nonce,
            "hmac": base64.b64encode(hmac).decode(),
        }

        return json.dumps({"success": final_payload}), 200
    else:
        return (
            json.dumps({"error": "Missing permissions to read document metadata"}),
            400,
        )


@app.route("/doc/clear/file-handle", methods=["POST"])
def doc_clear_file_handle():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    document_name = decrypted_payload["document_name"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Create document handle: hash(document name + organization name)
    document_handle = calculate_document_handle(document_name, organization_name)
    # Verify if document handle/name already exists in the organization
    if document_handle not in state["documents"]:
        return json.dumps({"error": "Document doesn't exist"}), 400
    else:
        document = state["documents"][document_handle]

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    # Verify client has correct permissions and save doc
    if has_permission(
        user_roles=user_roles, permission="doc_delete", document=document
    ):
        # Clear file handle
        state["documents"][document_handle]["file_handle"] = None
        return json.dumps({"message": "Document deleted"}), 200
    else:
        return json.dumps({"error": "Missing permissions to delete file handle"}), 400


@app.route("/doc/change/acl", methods=["POST"])
def doc_change_acl():
    data = request.get_json()

    session_validity = verify_session(state, data)
    if "error" in session_validity:
        return json.dumps(session_validity), 400

    payload_validity = decrypt_and_verify_payload(state, data)
    if "error" in payload_validity:
        return json.dumps(payload_validity), 400
    decrypted_payload = payload_validity["payload"]
    organization_name = decrypted_payload["organization"]
    username = decrypted_payload["username"]
    document_name = decrypted_payload["document_name"]
    operation = decrypted_payload["operation"]
    role_to_modify = decrypted_payload["role"]
    permission = decrypted_payload["permission"]

    # Verify if organization exists
    if organization_name not in state["organizations"]:
        return json.dumps({"error": "Organization doesn't exist"}), 400

    # Verify if user exists inside organization
    if username not in state["organizations"][organization_name]["subjects"]:
        return json.dumps({"error": "Username doesn't exist"}), 400

    # Create document handle: hash(document name + organization name)
    document_handle = calculate_document_handle(document_name, organization_name)
    # Verify if document handle/name already exists in the organization
    if document_handle not in state["documents"]:
        return json.dumps({"error": "Document doesn't exist"}), 400

    # Get client roles (only active ones are considered)
    organization = state["organizations"][organization_name]
    session_id = data["session_id"]
    user_roles = [
        role
        for role in state["sessions"][session_id]["roles"]
        if organization["acl"][role]["status"] == "active"
    ]

    document = state["documents"][document_handle]
    # Verify client has correct permissions and save doc
    if has_permission(user_roles=user_roles, permission="doc_acl", document=document):
        # Check if operation is valid
        if operation not in ("+", "-"):
            return json.dumps({"error": "Invalid operation"}), 400

        # Check if permission to add exists
        if permission not in ["doc_acl", "doc_read", "doc_delete"]:
            return json.dumps({"error": "Permission does not exist"}), 400

        # Check if target role exists
        if role_to_modify not in organization["acl"]:
            return (
                json.dumps({"error": "Role to modify does not exist"}),
                400,
            )

        document = state["documents"][document_handle]
        if role_to_modify in document["acl"]:
            if operation == "+":
                document["acl"][role_to_modify].append(permission)
            elif operation == "-":
                if permission in document["acl"][role_to_modify]:
                    document["acl"][role_to_modify].remove(permission)
                else:
                    return (
                        json.dumps({"error": "Role doesn't have this permission"}),
                        400,
                    )
        else:
            if operation == "+":
                document["acl"][role_to_modify] = [permission]
            elif operation == "-":
                return json.dumps({"error": "Role doesn't have this permission"}), 400
        return json.dumps({"message": "Document acl updated successfully"}), 200
    else:
        return json.dumps({"error": "Missing permissions to change document acl"}), 400


# <----------------------------->


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
