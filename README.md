# Secure Document Repository

A cryptographically secured document repository with role-based access control, built from scratch using Python. The system follows a client-server architecture where all communication is encrypted and integrity-verified, documents are stored encrypted at rest, and every operation is gated behind a session-authenticated, permission-checked API.

Designed and implemented as a personal project to explore applied cryptography and access control system design.

---

## Table of Contents

- [Overview](#overview)
- [Security Architecture](#security-architecture)
- [System Architecture](#system-architecture)
- [Access Control Model](#access-control-model)
- [Command Reference](#command-reference)
- [Getting Started](#getting-started)
- [Walkthrough Demo](#walkthrough-demo)
- [Project Structure](#project-structure)

---

## Overview

The repository server exposes a REST API (Flask) that manages organizations, subjects (users), roles, permissions, and encrypted documents. Clients interact with it through a CLI that handles all cryptographic operations locally before sending requests.

Key properties of the system:

- Documents are **encrypted at rest** using AES-CBC with a per-document random key
- The document key is itself **encrypted with the repository's RSA public key**, so only the server can decrypt it — and only to subjects with the right permissions
- All authenticated/authorized API traffic is **encrypted with AES-CBC and integrity-protected with HMAC-SHA256**, using session-scoped keys negotiated at session creation
- Session establishment uses **RSA-OAEP** for key exchange and **RSA-PSS** for client authentication, preventing both eavesdropping and impersonation
- **Replay attacks** are mitigated via a monotonically incrementing 128-bit nonce tracked per session
- Sessions **expire after 1 hour**

---

## Security Architecture

### Session Establishment

Session creation is the most security-sensitive flow in the system. The client:

1. Generates a fresh 256-bit symmetric key, split into a 128-bit **encryption key** and a 128-bit **integrity key**
2. Encrypts the symmetric key with the **repository's RSA-2048 public key** (OAEP/SHA-256)
3. **Signs** the encrypted key with the client's own **RSA private key** (PSS/SHA-256), proving identity
4. Computes an **HMAC-SHA256** over the encrypted key using the integrity key
5. Encrypts the identity payload (org, username, public key) with the encryption key using **AES-CBC** with a random IV
6. Sends all of this to the server in a single request

The server decrypts the symmetric key with its private key, verifies the signature against the registered public key, verifies the HMAC, and if all checks pass, creates a session. From this point on, all request payloads from that client are encrypted with the session keys.

```
Client                                      Server
  |                                            |
  |-- Generate 256-bit session key ----------->|
  |-- Encrypt key with REP_PUB_KEY (OAEP) ---->|
  |-- Sign encrypted key with CLIENT_PRIV ---->|
  |-- HMAC encrypted key with integrity_key -->|
  |-- Encrypt identity payload (AES-CBC) ----->|
  |                                            |-- Decrypt key (RSA priv)
  |                                            |-- Verify PSS signature
  |                                            |-- Verify HMAC
  |<-- session_id + expiration_time -----------|
```

### Per-Request Security

Every authenticated and authorized request wraps its payload in the following envelope:

- **Encrypted payload**: the JSON body, encrypted with AES-CBC using the session encryption key and a fresh random IV
- **HMAC**: computed over `session_id || plaintext_payload || iv || nonce` (and optionally `|| encrypted_document`) using the session integrity key
- **Nonce**: the next value in a monotonically incrementing counter, preventing replay

The server verifies session validity, nonce freshness, and HMAC integrity before decrypting and processing any request.

### Document Encryption

When a client uploads a document:

1. The client generates a random 128-bit AES key and encrypts the file with **AES-CBC**
2. The encrypted file and the per-document key are both sent to the server (the key travels inside the already-encrypted session payload)
3. The server re-encrypts the document key with its **RSA public key** (OAEP) before persisting it
4. The raw file is stored on disk under its SHA-256 content hash as the filename

When a client with `doc_read` permission fetches document metadata, the server decrypts the stored document key with its RSA private key and returns it to the client inside the encrypted session response. The client can then use the key and IV from the metadata to decrypt the file content locally.

This means the plaintext document key **never touches disk** and is only ever transmitted inside an encrypted, integrity-verified session channel.

---

## System Architecture

```
┌─────────────────────────────────────────────────┐
│  Client Container (Docker)                       │
│                                                  │
│  client.py          — CLI argument parser        │
│  anonymous_api_commands.py  — no session needed  │
│  authenticated_api_commands.py  — session needed │
│  authorized_api_commands.py — permission needed  │
│  local_commands.py  — runs entirely offline      │
│  utils.py           — crypto + payload helpers   │
└────────────────────┬────────────────────────────┘
                     │ HTTP (encrypted payloads)
                     │
┌────────────────────▼────────────────────────────┐
│  Repository Server Container (Docker)            │
│                                                  │
│  repository.py      — Flask REST API (~1500 LOC) │
│  crypto_utils.py    — AES-CBC, HMAC, nonce       │
│  utils.py           — session/payload validation │
│                                                  │
│  State: organizations.json, sessions.json,       │
│         documents.json, docs/ (encrypted files)  │
└─────────────────────────────────────────────────┘
```

Both components are containerized and communicate over a private Docker bridge network. The server exposes port 5000. The client container automatically discovers the server via the `REP_ADDRESS` environment variable.

---

## Access Control Model

The system implements a **Role-Based Access Control (RBAC)** model with two distinct permission scopes:

**Organization-level permissions** govern administrative operations:

| Permission    | Description                                      |
|---------------|--------------------------------------------------|
| `subject_new` | Add a new subject to the organization            |
| `subject_down`| Suspend a subject                                |
| `subject_up`  | Reactivate a subject                             |
| `role_new`    | Create a new role                                |
| `role_down`   | Suspend a role                                   |
| `role_up`     | Reactivate a role                                |
| `role_mod`    | Assign/remove roles and permissions              |
| `role_acl`    | Manage role ACLs                                 |
| `doc_new`     | Upload documents                                 |

**Document-level permissions** are stored in each document's ACL and govern access to that specific document:

| Permission   | Description                                      |
|--------------|--------------------------------------------------|
| `doc_read`   | Read document content and metadata               |
| `doc_delete` | Clear the document's file handle (soft delete)   |
| `doc_acl`    | Modify the document's ACL                        |

Every organization is bootstrapped with a `manager` role that holds all organization-level permissions. The creator is automatically assigned this role. Roles can be suspended (freezing all permissions for holders of that role) without deleting them. The last remaining manager of an organization cannot be suspended.

Subjects only have access to roles they explicitly assume within a session — holding a role in the organization does not automatically activate it.

---

## Command Reference

### Local Commands
These run entirely on the client machine with no server connection.

| Command | Usage | Description |
|---------|-------|-------------|
| `rep_subject_credentials` | `<password> <output_file>` | Generate an RSA key pair and save to a credentials file |
| `rep_decrypt_file` | `<encrypted_file> <metadata_file>` | Decrypt a previously retrieved document using its metadata |

### Anonymous API Commands
No session required.

| Command | Usage | Description |
|---------|-------|-------------|
| `rep_create_org` | `<org> <username> <name> <email> <credentials_file>` | Register a new organization |
| `rep_list_orgs` | | List all registered organizations |
| `rep_create_session` | `<org> <username> <password> <credentials_file> <session_file>` | Authenticate and create a session |
| `rep_get_file` | `<file_handle> [output_file]` | Fetch an encrypted file by its content hash |

### Authenticated API Commands
Require an active session file; no specific permissions needed.

| Command | Usage | Description |
|---------|-------|-------------|
| `rep_assume_role` | `<session_file> <role>` | Activate a role for the current session |
| `rep_drop_role` | `<session_file> <role>` | Deactivate a role from the current session |
| `rep_list_roles` | `<session_file>` | List all roles active in the current session |
| `rep_list_subjects` | `<session_file> [username]` | List subjects (optionally filtered) |
| `rep_list_role_subjects` | `<session_file> <role>` | List subjects assigned to a role |
| `rep_list_subject_roles` | `<session_file> <username>` | List roles assigned to a subject |
| `rep_list_role_permissions` | `<session_file> <role>` | List permissions of a role |
| `rep_list_permission_roles` | `<session_file> <permission>` | List roles that hold a given permission |
| `rep_list_docs` | `<session_file> [-s username] [-d nt\|ot\|et date]` | List documents, optionally filtered by creator or date |

### Authorized API Commands
Require an active session and the appropriate permission.

| Command | Usage | Permission |
|---------|-------|------------|
| `rep_add_subject` | `<session_file> <username> <name> <email> <credentials_file>` | `subject_new` |
| `rep_suspend_subject` | `<session_file> <username>` | `subject_down` |
| `rep_activate_subject` | `<session_file> <username>` | `subject_up` |
| `rep_add_role` | `<session_file> <role>` | `role_new` |
| `rep_suspend_role` | `<session_file> <role>` | `role_down` |
| `rep_reactivate_role` | `<session_file> <role>` | `role_up` |
| `rep_add_permission` | `<session_file> <role> <username_or_permission>` | `role_mod` |
| `rep_remove_permission` | `<session_file> <role> <username_or_permission>` | `role_mod` |
| `rep_add_doc` | `<session_file> <document_name> <file>` | `doc_new` |
| `rep_get_doc_metadata` | `<session_file> <document_name>` | `doc_read` |
| `rep_get_doc_file` | `<session_file> <document_name> [output_file]` | `doc_read` |
| `rep_delete_doc` | `<session_file> <document_name>` | `doc_delete` |
| `rep_acl_doc` | `<session_file> <document_name> <+\|-> <role> <permission>` | `doc_acl` |

---

## Getting Started

**The only requirement is [Docker](https://docs.docker.com/get-docker/).** Everything else is installed inside the containers automatically.

```bash
git clone https://github.com/your-username/secure-document-repository
cd secure-document-repository
./start.sh
```

`start.sh` builds and starts the server container, waits for it to pass its health check (polling `/pub_key`), then launches the interactive client container. When you exit the client, both containers are torn down cleanly.

Once inside the client container, you'll see the welcome screen. Run `help_commands.sh` at any time to see available commands grouped by category.

---

## Walkthrough Demo

A full end-to-end walkthrough script is included that exercises every feature of the system. It follows a narrative with two users — Alice and Bob — across 10 chapters:

1. Alice generates credentials and creates an organization
2. Alice opens a session and assumes the manager role
3. Alice invites Bob and adds him as a subject
4. Alice creates an `admin` role and assigns permissions and members
5. Bob's account is suspended and then reactivated
6. Roles are suspended, reactivated, and introspected
7. Bob uploads three files of varying sizes; Alice uploads a text document
8. Documents are listed with filters by creator and date
9. Document ACLs are modified (permissions granted and revoked per role)
10. A document is fetched, its handle is deleted from the repository, and the file is recovered and decrypted offline using the saved metadata

To run it:

```bash
# Inside the client container
./run_test.sh
```

The script pauses between chapters so you can inspect the output at each step.

---

## Project Structure

```
.
├── client/
│   ├── client.py                    # CLI entry point and argument parser
│   ├── local_commands.py            # Offline commands (keygen, decrypt)
│   ├── anonymous_api_commands.py    # Unauthenticated API calls
│   ├── authenticated_api_commands.py# Session-authenticated API calls
│   ├── authorized_api_commands.py   # Permission-gated API calls
│   ├── utils.py                     # AES-CBC, HMAC, nonce, payload builder
│   ├── commands/                    # Shell wrappers for each CLI command
│   ├── help_commands.sh             # Command listing helper
│   ├── welcome.sh                   # Interactive shell welcome screen
│   ├── run_test.sh                  # Full walkthrough test script
│   └── Dockerfile
│
├── repository/
│   ├── repository.py                # Flask REST API server (~1500 LOC)
│   ├── crypto_utils.py              # AES-CBC, HMAC, nonce primitives
│   ├── utils.py                     # Session verification, payload decryption
│   └── Dockerfile
│
├── docker-compose.yml               # Service definitions and networking
└── start.sh                         # One-command launcher
```

---

## Dependencies

| Component  | Stack |
|------------|-------|
| Server     | Python 3, Flask, cryptography |
| Client     | Python 3, requests, cryptography |
| Transport  | HTTP over a private Docker bridge network |
| Crypto     | RSA-2048 (OAEP/PSS), AES-128-CBC, HMAC-SHA256, SHA-256 |
