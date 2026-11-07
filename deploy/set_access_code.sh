#!/usr/bin/env bash
# Turns on live URL scans by setting the access code people must enter to scan real
# links. Input is hidden and never printed. Run from your own machine with a terminal:
#   ssh -t root@<vm-ip> /opt/link-detonator/deploy/set_access_code.sh
set -euo pipefail

ENV_FILE=/etc/link-detonator/app.env
[[ -t 0 ]] || { echo "No terminal: run this through 'ssh -t' so the code stays hidden." >&2; exit 1; }

read -rsp "Choose an access code (at least 12 characters, no spaces): " code
echo
if [[ ${#code} -lt 12 || "$code" =~ [[:space:]] ]]; then
  echo "Too short or contains spaces. Nothing changed." >&2
  exit 1
fi
read -rsp "Type it again: " again
echo
[[ "$code" == "$again" ]] || { echo "The two entries differ. Nothing changed." >&2; exit 1; }

sed -i '/^LD_LIVE_ACCESS_CODE=/d' "$ENV_FILE"
printf 'LD_LIVE_ACCESS_CODE=%s\n' "$code" >>"$ENV_FILE"
chmod 640 "$ENV_FILE"
unset code again
systemctl restart link-detonator.service
echo "Saved. Live URL scans are on for anyone who enters this code. The app was restarted."
