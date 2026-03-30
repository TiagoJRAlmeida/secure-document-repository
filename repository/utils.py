import os
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def rep_keys():
    if not os.path.exists("rep_pub_key.pem") or not os.path.exists("rep_priv_key.pem"):
        password = os.environ.get("REPOSITORY_PASSWORD", "password12345")
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
