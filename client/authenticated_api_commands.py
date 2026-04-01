import sys
import json
import requests
import logging
from utils import *


logging.basicConfig(format="[%(levelname)s] %(message)s")
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def rep_assume_role(state, session_file, role):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Verify if client already has the role
    if role in session_data["roles"]:
        logger.info("You already have that role.")
        sys.exit(0)

    # Define base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "role": role,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/assume"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        session_data["roles"].append(role)
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        logger.info(f"Role {role} assumed successfully.")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_drop_role(state, session_file, role):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Check if the client has the role in the current section
    if role not in session_data["roles"]:
        logger.info("You dont have that role to drop.")
        sys.exit(0)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "role": role,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/drop"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        session_data["roles"].remove(role)
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)
        logger.info(f"Role {role} dropped successfully")
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


# List all roles and their state in the organization of the current session
def rep_list_roles(state, session_file):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_username": None,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        roles_and_status = response.json()
        message = ""
        title = "Roles"
        if not roles_and_status:
            message = "No current roles"
        else:
            for index, role in enumerate(roles_and_status):
                message += f"Role {index + 1} - {role}: {roles_and_status[role]}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_list_subjects(state, session_file, username=None):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_username": username,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/subject/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        usernames_and_status = response.json()
        message = ""
        title = "Subjects"
        if not usernames_and_status:
            message = "No current subjects"
        else:
            for index, username in enumerate(usernames_and_status):
                message = f"Subject {index + 1} - {username}: {usernames_and_status[username]}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


# List all subjects that have the specified role
def rep_list_role_subjects(state, session_file, role):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_role": role,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/list/subjects"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        subjects_list = response.json()
        title = "Subjects"
        message = ""
        if not subjects_list:
            message = "No current subjects with that role."
        else:
            for index, subject in enumerate(subjects_list):
                message += f"Subject {index + 1} - {subject}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


# List all roles of a specific subject
def rep_list_subject_roles(state, session_file, username):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_username": username,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        roles_and_status = response.json()
        title = "Roles"
        message = ""
        if not roles_and_status:
            message = "No current roles"
        else:
            for index, role in enumerate(roles_and_status):
                message += f"Role {index + 1} - {role}: {roles_and_status[role]}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_list_role_permissions(state, session_file, role):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_role": role,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/role/list/permissions"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        role_permissions = response.json()
        title = f"{role} Permissions"
        message = ""
        if not role_permissions:
            message = "Role has no permissions"
        else:
            for index, permission in enumerate(role_permissions):
                message += f"Permission {index + 1}: {permission}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_list_permission_roles(state, session_file, permission):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_permission": permission,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state['REP_ADDRESS']}/permission/list/role"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        permission_roles = response.json()
        message = ""
        if permission_roles["type"] == "Organization roles":
            title = f"Organization roles with {permission} permission"
            if not permission_roles["roles"]:
                message = "No organization roles with that permission"
            else:
                # TO-DO: Check this shit
                for index, role in enumerate(permission_roles["roles"]):
                    message += f"Role {index + 1}: {role}\n"
        else:
            title = f"Documents with roles with {permission} permission"
            if not permission_roles["roles"]:
                message = "No documents with roles with that permission"
            else:
                for document_name in permission_roles["roles"]:
                    message += f"Document {document_name}: {permission_roles["roles"][document_name]}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)


def rep_list_docs(state, session_file, username=None, date_relation=None, date=None):
    # Read session file and get necessary data
    with open(session_file, "r") as sf:
        session_data = json.load(sf)

    # Define the base payload
    base_payload = {
        "organization_name": session_data["organization_name"],
        "username": session_data["username"],
        "filter_username": username,
        "filter_date_relation": date_relation,
        "filter_date": date,
    }

    final_payload = prepare_final_payload(base_payload, session_data)
    url = f"http://{state["REP_ADDRESS"]}/doc/list"
    response = requests.post(url, json=final_payload)

    if response.status_code == 200:
        session_data["keys"]["nonce"] = final_payload["nonce"]
        with open(session_file, "w") as sf:
            json.dump(session_data, sf)

        docs = response.json().get("documents")
        title = "Documents"
        message = ""
        if not docs and not any([username, date_relation, date]):
            message = "No current documents in the organization"
        elif not docs and any([username, date_relation, date]):
            message = "No documents that meet the requirements"
        else:
            for index, doc in enumerate(docs):
                message += f"Document {index + 1} - Name: {doc[0]} - Creator: {doc[1]} - Creation date: {doc[2]}\n"
        pretty_print(title=title, message=message)
        sys.exit(0)
    else:
        logger.error(f"{response.status_code} - {response.json().get("error")}")
        sys.exit(1)
