import shutil
import sys
import os
import json
import requests
import base64
from local_commands import *
from anonymous_api_commands import rep_get_file
from utils import *


def rep_add_subject(state, session_file, username, name, email, credentials_file):
    # Abrir e carregar o conteúdo do arquivo JSON de chaves
    with open(credentials_file, "r") as f:
        keys_file = json.load(f)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Preparar o payload para cifrar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "new_subject": [username, name, email, keys_file["PUBLIC_KEY"]],
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Usamos a encryption_key para cifrar o payload
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/subject/create"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Subject added successfully")
        sys.exit(0)
    else:
        print(
            f"Error when adding subject: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_suspend_subject(state, session_file, username):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Preparar o payload para cifrar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "subject_to_suspend": username,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Usamos a encryption_key para cifrar o payload
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    # Enviar o pedido de listagem
    url = f"http://{state['REP_ADDRESS']}/subjects/suspend"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Operation successful")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_activate_subject(state, session_file, username):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Preparar o payload para cifrar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "subject_to_activate": username,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Usamos a encryption_key para cifrar o payload
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    # Enviar o pedido de listagem
    url = f"http://{state['REP_ADDRESS']}/subjects/activate"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Operation successful")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_add_role(state, session_file, role):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/role/add"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Role created successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_suspend_role(state, session_file, role):
    # O role do manager não pode ser suspenso
    if role == "MANAGER":
        print("MANAGER role can't be suspended")
        sys.exit(-1)

    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
        "operation": "suspend",
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/role/change/status"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Role status changed successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_reactivate_role(state, session_file, role):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
        "operation": "reactivate",
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/role/change/status"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Role status changed successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_add_permission(state, session_file, role, username_or_permission):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
        "username_or_permission": username_or_permission,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/role/add/permission"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print(f"Operation successful: {response.json().get("message")}")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_remove_permission(state, session_file, role, username_or_permission):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
        "username_or_permission": username_or_permission,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/role/remove/permission"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print(f"Operation successful: {response.json().get("message")}")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_add_doc(state, session_file, document_name, file_path):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Verificar se o caminho para o ficheiro existe
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        sys.exit(-1)

    # Abrir o fichero
    with open(file_path, "rb") as f:
        file_content = f.read()

    # Calcular o hash do ficheiro para servir como file_handle
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_content)
    file_hash = digest.finalize()

    # Criar uma key secreta para encriptar o ficheiro (128 bits)
    secret_key = os.urandom(16)

    # Encriptar o conteúdo do ficheiro com a chave aleatória simétrica
    encrypted_document_content, document_iv = encrypt_data_AES_CBC(
        file_content, secret_key
    )

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "secret_key": base64.b64encode(secret_key).decode(),
        "document_iv": base64.b64encode(document_iv).decode(),
        "document_name": document_name,
        "file_handle": base64.b64encode(file_hash).decode(),
        "algorithm": "AES-CBC",
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = (
        session_id.encode()
        + encrypted_document_content
        + payload_bytes
        + payload_iv
        + nonce
    )
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "encrypted_document_content": base64.b64encode(
            encrypted_document_content
        ).decode(),
        "payload_iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/doc/create"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Document added successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_get_doc_metadata(state, session_file, document_name=None):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "document_name": document_name,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "payload_iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/doc/get/metadata"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        data = response.json()
        received_encrypted_payload = base64.b64decode(data["encrypted_payload"])
        received_payload_iv = base64.b64decode(data["payload_iv"])
        received_nonce = base64.b64decode(data["nonce"])
        received_hmac_signature = base64.b64decode(data["hmac"])

        # Verificar se o nonce é válido
        if base64.b64encode(received_nonce).decode() in session_data["KEYS"]["NONCE"]:
            print("Error: Nonce not valid")
            sys.exit(-1)

        # Desencriptar o payload
        decrypted_payload = decrypt_data_AES_CBC(
            received_encrypted_payload, encryption_key, received_payload_iv
        )

        # Serializar o payload e verificar se o HMAC é valido
        payload_bytes = json.dumps(decrypted_payload).encode()
        message = payload_bytes + received_payload_iv + received_nonce
        calculated_hmac_signature = calculate_hmac(message, integrity_key)

        if calculated_hmac_signature != received_hmac_signature:
            print("Error: HMAC not valid")
            sys.exit(-1)

        print(json.dumps(decrypted_payload))
        return json.dumps(decrypted_payload)

    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_get_doc_file(state, session_file, document_name, output_file=None):

    # "Silencia-mos" os prints
    original_stdout = sys.stdout
    sys.stdout = open(os.devnull, "w")
    document_metadata = rep_get_doc_metadata(state, session_file, document_name)
    file_handle = json.loads(document_metadata)["file_handle"]
    encrypted_file_content = rep_get_file(state, file_handle)
    file_content = rep_decrypt_file(encrypted_file_content, document_metadata)
    sys.stdout = original_stdout

    if output_file:
        with open(output_file, "w") as f:
            f.write(file_content)
            sys.exit(0)

    terminal_width = shutil.get_terminal_size().columns
    bar_size = int((terminal_width - len("File Content") - 4) / 2)
    print("\n+" + ("-" * bar_size) + " File Content " + ("-" * bar_size) + "+\n")
    print(file_content)
    print("\n+" + ("-" * (terminal_width - 2)) + "+\n")
    sys.exit(0)


def rep_delete_doc(state, session_file, document_name):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "document_name": document_name,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/doc/clear/file-handle"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Document deleted successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_acl_doc(state, session_file, document_name, operation, role, permission):
    # Verificar se o caminho para o ficheiro de sessão
    if not os.path.exists(session_file):
        print(f"File not found: {session_file}")
        sys.exit(-1)

    # Abrir o session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Carregar o session_id
    session_id = session_data["SESSION_ID"]

    # Preparar o payload para enviar
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "document_name": document_name,
        "operation": operation,
        "role": role,
        "permission": permission,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Encriptar o payload para enviar
    payload_bytes = json.dumps(payload).encode()
    encrypted_payload, payload_iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

    # Gerar o hmac
    message = session_id.encode() + payload_bytes + payload_iv + nonce
    hmac_signature = calculate_hmac(message, integrity_key)

    final_payload = {
        "session_id": session_id,
        "encrypted_payload": base64.b64encode(encrypted_payload).decode(),
        "iv": base64.b64encode(payload_iv).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "hmac": base64.b64encode(hmac_signature).decode(),
    }

    url = f"http://{state['REP_ADDRESS']}/doc/change/acl"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Document ACL updated successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)
