bold=$(tput bold)
normal=$(tput sgr0)
dim=$(tput dim 2>/dev/null || echo "")

print_section() {
  echo ""
  printf "  ${bold}$1${normal}\n"
  printf "  ${dim}$2${normal}\n"
}

if [ "$1" = "-v" ]; then
  echo "Work in progress..."
elif [ $# -eq 0 ]; then
  echo ""
  echo "  Commands for communicating with the repository API."
  echo "  Run any command with --help for detailed usage."

  print_section "Local commands" "Executed locally — no server connection needed"
  echo "    rep_subject_credentials  rep_decrypt_file"

  print_section "Anonymous API commands" "Server commands — no active session required"
  echo "    rep_create_org  rep_list_orgs  rep_create_session  rep_get_file"

  print_section "Authenticated API commands" "Requires an active session on the target organization"
  echo "    rep_assume_role       rep_drop_role         rep_list_roles"
  echo "    rep_list_subjects     rep_list_role_subjects  rep_list_subject_roles"
  echo "    rep_list_role_permissions  rep_list_permission_roles  rep_list_docs"

  print_section "Authorized API commands" "Requires an active session and correct permissions"
  echo "    rep_add_subject    rep_suspend_subject  rep_activate_subject"
  echo "    rep_add_role       rep_suspend_role     rep_reactivate_role"
  echo "    rep_add_permission rep_remove_permission"
  echo "    rep_add_doc        rep_get_doc_metadata rep_get_doc_file"
  echo "    rep_delete_doc     rep_acl_doc"
  echo ""
  echo "  Usage: ./help_commands.sh [-v]"
  echo ""
else
  echo "Usage: ./help_commands.sh [-v]"
fi
