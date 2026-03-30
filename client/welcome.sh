#!/bin/bash

bold=$(tput bold)
normal=$(tput sgr0)
dim=$(tput dim 2>/dev/null || echo "")
cols=70

divider=""
for ((i=0; i<cols; i++)); do
  divider+="─"
done

echo -e "
  ${divider}

    ██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗██╗
    ██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝██║
    ██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗  ██║
    ██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  ╚═╝
    ╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗██╗
     ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝╚═╝

  ${divider}

  ${bold}Secure Document Repository${normal} — Client

  Interact securely with the repository server using the available CLI commands.
  All sessions are encrypted. Permissions vary by command category.

  ${dim}Run ./help_commands.sh to list all available commands.${normal}

  ${divider}
"

exec bash
