#!/usr/bin/env bash
# Stores the Vultr Serverless Inference key on the VM and tests it. The key is read with
# input hidden and is never printed. Run from your own machine with a terminal:
#   ssh -t root@<vm-ip> /opt/link-detonator/deploy/set_inference_key.sh
set -euo pipefail

ENV_FILE=/etc/link-detonator/app.env
[[ -t 0 ]] || { echo "No terminal: run this through 'ssh -t' so the key stays hidden." >&2; exit 1; }

read -rsp "Paste the Vultr inference key, then press Enter: " key
echo
if [[ -z "$key" || "$key" =~ [[:space:]] || ${#key} -lt 20 || ${#key} -gt 200 ]]; then
  echo "That does not look like an API key (empty, has spaces, or wrong length). Nothing saved." >&2
  exit 1
fi

sed -i '/^VULTR_API_KEY=/d' "$ENV_FILE"
printf 'VULTR_API_KEY=%s\n' "$key" >>"$ENV_FILE"
chmod 640 "$ENV_FILE"

model=$(grep '^LD_LLM_MODEL=' "$ENV_FILE" | cut -d= -f2- || true)
model=${model:-glm-5.3-flash}
code=$(curl -s -o /dev/null -w '%{http_code}' -m 60 https://api.vultrinference.com/v1/chat/completions \
  -H "Authorization: Bearer $key" -H 'Content-Type: application/json' \
  -d "{\"model\":\"$model\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with OK.\"}],\"max_tokens\":5}")
unset key

systemctl restart link-detonator.service
if [[ "$code" == "200" ]]; then
  echo "Saved. Test call to $model succeeded (HTTP 200). The app was restarted."
else
  echo "Saved, but the test call to $model returned HTTP $code. Check the key and subscription." >&2
  exit 1
fi
