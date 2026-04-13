#!/bin/bash

# ─── Styling ────────────────────────────────────────────────────────────────

BOLD="\033[1m"
DIM="\033[2m"
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
RESET="\033[0m"

cols=70
divider=""
for ((i=0; i<cols; i++)); do divider+="─"; done

# ─── Helper functions ────────────────────────────────────────────────────────

section() {
  echo -e "\n${divider}"
  echo -e "\n  ${BOLD}$1${RESET}"
  echo -e "  ${DIM}$2${RESET}\n"
}

step() {
  echo -e "  ${CYAN}›${RESET} ${BOLD}$1${RESET}"
  echo -e "  ${DIM}$2${RESET}"
}

removed() {
  echo -e "  ${DIM}removed  $1${RESET}"
}

created() {
  echo -e "  ${DIM}created  $1${RESET}"
}

continue_prompt() {
  echo -e "\n  ${DIM}${divider}${RESET}"
  echo -en "  ${DIM}Press Enter to continue... (Ctrl + C to quit)${RESET} "
  read -r
}

# ─── Intro ───────────────────────────────────────────────────────────────────

echo -e "\n${divider}\n"
echo -e "  ${BOLD}Repository System — Walkthrough Test${RESET}\n"
echo -e "  ${DIM}This script demonstrates the full workflow of the repository system."
echo -e "  It follows Alice, who creates an organization and manages it end-to-end:"
echo -e "  adding subjects, assigning roles, uploading documents, tweaking ACLs,"
echo -e "  and finally retrieving encrypted files using a saved file handle.${RESET}"
echo -e "\n${divider}"

continue_prompt

# ─── Setup ───────────────────────────────────────────────────────────────────

section "Setup" "Cleaning up leftover files from previous runs and generating fresh test assets."

step "Removing leftover files" "Deleting keys, sessions, test files and repository state from prior runs."

for f in \
  "alice_keys.json" \
  "bob_keys.json" \
  "alice_session.json" \
  "bob_session.json" \
  "rep_pub_key.pem" \
  "test_file_10Kb" \
  "test_file_100Kb" \
  "test_file_1Mb" \
  "small_story.txt" \
  "metadata.json"
do
  if test -f "$f"; then
    rm "$f"
    removed "$f"
  fi
done

echo ""
step "Creating test files" "Generating binary files of various sizes and a small text document."

dd if=/dev/zero of="test_file_10Kb"  bs=10K  count=1 > /dev/null 2>&1
created "test_file_10Kb"

dd if=/dev/zero of="test_file_100Kb" bs=100K count=1 > /dev/null 2>&1
created "test_file_100Kb"

dd if=/dev/zero of="test_file_1Mb"   bs=1M   count=1 > /dev/null 2>&1
created "test_file_1Mb"

cat > "small_story.txt" <<'EOF'
In a quiet village, a boy named Liam discovered a hidden key buried
in his garden. That night, he dreamt of a glowing door in the forest.
The next day, curiosity led him to the woods, where the key fit perfectly
into the mysterious door. As it creaked open, a dazzling world of floating
islands and golden skies lay before him. Liam stepped through, knowing
his life would never be the same.
EOF
created "small_story.txt"

continue_prompt

# ─── Alice creates credentials and an organisation ───────────────────────────

section "Chapter 1 — Alice sets up shop" \
  "Alice generates her credentials and founds a new organisation."

step "Generating Alice's credentials" "rep_subject_credentials"
rep_subject_credentials 1234 "alice_keys.json"

echo ""
step "Creating organisation 'AliceCorp'" "rep_create_org"
rep_create_org AliceCorp Alice Alice alice@example.com "alice_keys.json"

echo ""
step "Verifying the organisation was created" "rep_list_orgs"
rep_list_orgs

continue_prompt

# ─── Alice opens a session and assumes the Manager role ──────────────────────

section "Chapter 2 — Alice takes charge" \
  "Alice opens a session inside AliceCorp and assumes the default MANAGER role."

step "Creating a session inside AliceCorp" "rep_create_session"
rep_create_session AliceCorp Alice 1234 "alice_keys.json" "alice_session.json"

echo ""
step "Assuming the manager role" "rep_assume_role"
rep_assume_role "alice_session.json" "manager"

continue_prompt

# ─── Alice invites Bob ───────────────────────────────────────────────────────

section "Chapter 3 — Bob joins the organisation" \
  "Alice generates credentials for Bob and adds him to AliceCorp."

step "Generating Bob's credentials" "rep_subject_credentials"
rep_subject_credentials 1234 "bob_keys.json"

echo ""
step "Adding Bob as a subject" "rep_add_subject"
rep_add_subject "alice_session.json" Bob Bob bob@example.com "bob_keys.json"

echo ""
step "Verifying Bob was added" "rep_list_subjects"
rep_list_subjects "alice_session.json"

continue_prompt

# ─── Roles and permissions ───────────────────────────────────────────────────

section "Chapter 4 — Roles and permissions" \
  "Alice creates an admin role, grants it permissions, and assigns it to both herself and Bob."

step "Adding the admin role" "rep_add_role"
rep_add_role "alice_session.json" "admin"

echo ""
step "Granting subject_down to admin" "rep_add_permission"
rep_add_permission "alice_session.json" admin subject_down

echo ""
step "Granting subject_up to admin" "rep_add_permission"
rep_add_permission "alice_session.json" admin subject_up

echo ""
step "Assigning admin role to Alice" "rep_add_permission"
rep_add_permission "alice_session.json" admin Alice

echo ""
step "Assigning admin role to Bob" "rep_add_permission"
rep_add_permission "alice_session.json" admin Bob

continue_prompt

# ─── Subject suspension cycle ────────────────────────────────────────────────

section "Chapter 5 — Suspending and reactivating Bob" \
  "Alice tests the subject lifecycle by temporarily suspending Bob's account."

step "Suspending Bob" "rep_suspend_subject"
rep_suspend_subject "alice_session.json" Bob
rep_list_subjects   "alice_session.json" Bob

echo ""
step "Reactivating Bob" "rep_activate_subject"
rep_activate_subject "alice_session.json" Bob
rep_list_subjects    "alice_session.json" Bob

continue_prompt

# ─── Role lifecycle ──────────────────────────────────────────────────────────

section "Chapter 6 — Role lifecycle and permission introspection" \
  "Alice explores the role management commands: listing, suspending and reactivating."

step "Listing permissions on admin" "rep_list_role_permissions"
rep_list_role_permissions "alice_session.json" admin

echo ""
step "Listing roles that hold subject_up" "rep_list_permission_roles"
rep_list_permission_roles "alice_session.json" subject_up

echo ""
step "Suspending the admin role" "rep_suspend_role"
rep_suspend_role "alice_session.json" admin

step "Verifying admin is now suspended (Alice's roles)" "rep_list_subject_roles"
rep_list_subject_roles "alice_session.json" Alice

echo ""
step "Reactivating the admin role" "rep_reactivate_role"
rep_reactivate_role "alice_session.json" admin

step "Verifying admin is active again (Alice's roles)" "rep_list_subject_roles"
rep_list_subject_roles "alice_session.json" Alice

continue_prompt

# ─── Bob uploads documents ───────────────────────────────────────────────────

section "Chapter 7 — Bob uploads documents" \
  "Alice grants doc_new to admin so Bob can upload files. Bob then opens his own session and adds several documents."

step "Granting doc_new to admin" "rep_add_permission"
rep_add_permission "alice_session.json" admin doc_new

echo ""
step "Bob starts a session and assumes the admin role" "rep_create_session / rep_assume_role"
rep_create_session AliceCorp Bob 1234 "bob_keys.json" "bob_session.json"
rep_assume_role "bob_session.json" admin

echo ""
step "Bob uploads test_file_10Kb" "rep_add_doc"
rep_add_doc "bob_session.json" "test_file_10Kb" test_file_10Kb

step "Bob uploads test_file_100Kb" "rep_add_doc"
rep_add_doc "bob_session.json" "test_file_100Kb" test_file_100Kb

step "Bob uploads test_file_1Mb" "rep_add_doc"
rep_add_doc "bob_session.json" "test_file_1Mb" test_file_1Mb

echo ""
step "Alice uploads small_story.txt" "rep_add_doc"
rep_add_doc "alice_session.json" "small_story.txt" small_story

continue_prompt

# ─── Listing documents with filters ─────────────────────────────────────────

section "Chapter 8 — Browsing the document list" \
  "Alice inspects what was uploaded using various filter combinations."

step "All documents (no filter)" "rep_list_docs"
rep_list_docs "alice_session.json"

echo ""
step "Documents uploaded by Bob" "rep_list_docs -s Bob"
rep_list_docs "alice_session.json" -s Bob

echo ""
step "Bob's documents newer than 18-12-20" "rep_list_docs -s Bob -d nt 18-12-20"
rep_list_docs "alice_session.json" -s Bob -d nt 18-12-20

step "Bob's documents older than 18-12-20" "rep_list_docs -s Bob -d ot 18-12-20"
rep_list_docs "alice_session.json" -s Bob -d ot 18-12-20

step "Bob's documents from exactly 18-12-20" "rep_list_docs -s Bob -d et 18-12-20"
rep_list_docs "alice_session.json" -s Bob -d et 18-12-20

continue_prompt

# ─── ACL management ──────────────────────────────────────────────────────────

section "Chapter 9 — Access control lists" \
  "Alice modifies the ACL on test_file_1Mb, granting and then revoking permissions from the admin role."

step "Granting doc_read to admin on test_file_1Mb" "rep_acl_doc +"
rep_acl_doc "alice_session.json" test_file_1Mb + admin doc_read

step "Granting doc_acl to admin on test_file_1Mb" "rep_acl_doc +"
rep_acl_doc "alice_session.json" test_file_1Mb + admin doc_acl

step "Revoking doc_acl from admin on test_file_1Mb" "rep_acl_doc -"
rep_acl_doc "alice_session.json" test_file_1Mb - admin doc_acl

continue_prompt

# ─── File retrieval and decryption ───────────────────────────────────────────

section "Chapter 10 — Retrieving and decrypting files" \
  "Alice reads small_story, deletes its handle from the repository, then recovers the file using the saved handle and decrypts it."

step "Reading small_story via the session" "rep_get_doc_file"
rep_get_doc_file "alice_session.json" "small_story"

echo ""
step "Saving document metadata before deletion" "rep_get_doc_metadata"
rep_get_doc_metadata "alice_session.json" "small_story" > "metadata.json"
file_handle=$(jq -r '.file_handle' "metadata.json")

step "Deleting the document handle from the repository" "rep_delete_doc"
rep_delete_doc "alice_session.json" "small_story"

echo ""
step "Attempting to read small_story after deletion (expected to fail)" "rep_get_doc_file"
rep_get_doc_file "alice_session.json" "small_story"

echo ""
step "Fetching the raw encrypted file using the saved handle" "rep_get_file"
rep_get_file "$file_handle" "encrypted_content"

step "Decrypting the content with the saved metadata" "rep_decrypt_file"
rep_decrypt_file "encrypted_content" "metadata.json"

continue_prompt

# ─── Teardown ────────────────────────────────────────────────────────────────

echo -e "\n${divider}\n"
echo -e "  ${BOLD}${GREEN}Walkthrough complete.${RESET}  All steps finished successfully.\n"
echo -e "${divider}\n"
