import sys
import json
import requests
import shutil
from utils import *


def rep_assume_role(state, session_file, role):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Verificar se o subject não tem já a role
    if role in session_data["ROLES"]:
        print("You already have that role.")
        sys.exit(-1)

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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

    # Enviar o pedido de assumir
    url = f"http://{state['REP_ADDRESS']}/role/assume"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        session_data["ROLES"].append(role)
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Role assumed successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_drop_role(state, session_file, role):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Verificar se o subject tem a role
    if role not in session_data["ROLES"]:
        print("You dont have that role.")
        sys.exit(-1)

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "role": role,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/role/drop"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        session_data["ROLES"].remove(role)
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        print("Role dropped successfully")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


# Lista todas as roles e o seu estado da sessão atual
def rep_list_roles(state, session_file):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_username": None,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/role/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        roles_and_status = response.json()
        if not roles_and_status:
            print("No current roles")
            sys.exit(0)

        terminal_width = shutil.get_terminal_size().columns
        bar_size = int((terminal_width - len("Roles") - 4) / 2)
        print("\n+" + ("-" * bar_size) + " Roles " + ("-" * bar_size) + "+\n")

        for index, role in enumerate(roles_and_status):
            print(f"Role {index + 1} - {role}: {roles_and_status[role]}")

        print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_list_subjects(state, session_file, username=None):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_username": username,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/subject/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        usernames_and_status = response.json()
        if not usernames_and_status:
            print("No current subjects")
            sys.exit(0)

        terminal_width = shutil.get_terminal_size().columns
        bar_size = int((terminal_width - len("Subjects") - 4) / 2)
        print("\n+" + ("-" * bar_size) + " Subjects " + ("-" * bar_size) + "+\n")

        for index, username in enumerate(usernames_and_status):
            print(f"Subject {index + 1} - {username}: {usernames_and_status[username]}")

        print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


# Lista os subjects que tem uma role
def rep_list_role_subjects(state, session_file, role):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_role": role,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/role/list/subjects"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        subjects_list = response.json()
        if not subjects_list:
            print("No current subjects with that role.")
            sys.exit(0)

        terminal_width = shutil.get_terminal_size().columns
        bar_size = int(((terminal_width - len("Subjects") - 4) / 2))
        print("\n+" + ("-" * bar_size) + " Subjects " + ("-" * bar_size) + "+\n")

        for index, subject in enumerate(subjects_list):
            print(f"Subject {index + 1} - {subject}")

        print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


# Lista as roles de um subject
def rep_list_subject_roles(state, session_file, username):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_username": username,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/role/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        roles_and_status = response.json()
        if not roles_and_status:
            print("No current roles")
            sys.exit(0)

        terminal_width = shutil.get_terminal_size().columns
        bar_size = int((terminal_width - len("Roles") - 4) / 2)
        print("\n+" + ("-" * bar_size) + " Roles " + ("-" * bar_size) + "+\n")

        for index, role in enumerate(roles_and_status):
            print(f"Subject {index + 1} - {role}: {roles_and_status[role]}")

        print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_list_role_permissions(state, session_file, role):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_role": role,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/role/list/permissions"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        role_permissions = response.json()
        if not role_permissions:
            print("Role has no permissions")
            sys.exit(0)

        terminal_width = shutil.get_terminal_size().columns
        bar_size = int((terminal_width - len(f"{role} Permissions") - 4) / 2)
        print(
            "\n+"
            + ("-" * bar_size)
            + f" {role} Permissions "
            + ("-" * bar_size)
            + "+\n"
        )

        for index, permission in enumerate(role_permissions):
            print(f"Permission {index + 1}: {permission}")

        print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_list_permission_roles(state, session_file, permission):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_permission": permission,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serealizar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state['REP_ADDRESS']}/permission/list/role"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        permission_roles = response.json()
        if permission_roles["type"] == "Organization roles":
            terminal_width = shutil.get_terminal_size().columns
            bar_size = int(
                (
                    terminal_width
                    - len(f"Organization roles with {permission} permission")
                    - 4
                )
                / 2
            )
            print(
                "\n+"
                + ("-" * bar_size)
                + f" Organization roles with {permission} permission "
                + ("-" * bar_size)
                + "+\n"
            )

            if not permission_roles["roles"]:
                print("No organization roles with that permission")
                sys.exit(0)

            for index, role in enumerate(permission_roles["roles"]):
                print(f"Role {index + 1}: {role}")

            print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

            sys.exit(0)

        else:
            terminal_width = shutil.get_terminal_size().columns
            bar_size = int(
                (
                    terminal_width
                    - len(f"Documents with roles with {permission} permission")
                    - 4
                )
                / 2
            )
            print(
                "\n+"
                + ("-" * bar_size)
                + f" Documents with roles with {permission} permission "
                + ("-" * bar_size)
                + "+\n"
            )

            if not permission_roles["roles"]:
                print("No documents with roles with that permission")
                sys.exit(0)

            for document_name in permission_roles["roles"]:
                print(
                    f"Document {document_name}: {permission_roles["roles"][document_name]}"
                )

            print("\n+" + ("-" * (terminal_width - 2)) + "+\n")

            sys.exit(0)

    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)


def rep_list_docs(state, session_file, username=None, date_relation=None, date=None):
    # Ler os dados guardados na session file
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Obter o session_id
    session_id = session_data["SESSION_ID"]

    # Definir a payload
    payload = {
        "organization_name": session_data["ORGANIZATION_NAME"],
        "username": session_data["USERNAME"],
        "filter_username": username,
        "filter_date_relation": date_relation,
        "filter_date": date,
    }

    # Carregar as chaves do session_file
    encryption_key = base64.b64decode(session_data["KEYS"]["ENCRYPTION_KEY"])
    integrity_key = base64.b64decode(session_data["KEYS"]["INTEGRITY_KEY"])

    # Serializar o payload (não cifrado)
    payload_bytes = json.dumps(payload).encode()

    # Usamos a encryption_key para cifrar o payload
    encrypted_payload, iv = encrypt_data_AES_CBC(payload_bytes, encryption_key)

    # Geramos o proximo nonce
    nonce = calculate_next_nonce(base64.b64decode(session_data["KEYS"]["NONCE"]))

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
    url = f"http://{state["REP_ADDRESS"]}/doc/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["KEYS"]["NONCE"] = base64.b64encode(nonce).decode()
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        docs = response.json().get("documents")
        if not docs and not any([username, date_relation, date]):
            print("No current documents in the organization")
            sys.exit(0)
        elif not docs and any([username, date_relation, date]):
            print("No documents that meet the requirements")
            sys.exit(0)

        terminal_width = shutil.get_terminal_size().columns
        bar_size = int((terminal_width - len("Documents") - 4) / 2)
        print("\n+" + ("-" * bar_size) + " Documents " + ("-" * bar_size) + "+\n")

        for index, doc in enumerate(docs):
            print(
                f"Document {index + 1} - Name: {doc[0]} - Creator: {doc[1]} - Creation date: {doc[2]}"
            )

        print("\n+" + ("-" * (terminal_width - 2)) + "+\n")
        sys.exit(0)
    else:
        print(
            f"Operation Error: {response.status_code}\nError Message: {response.json().get("Error")}"
        )
        sys.exit(-1)
