#!/usr/bin/env bash
# Maintenance sequence for release cd875a3 (code bfff013). Any failed check runs rollback.sh.
set -uo pipefail
B=/root/release-backup-20261108
R=/root/release/tree-cd875a3
ENV=/etc/link-detonator/app.env
IMAGE_ID=sha256:1b88871c6c6de4b4c8f8ed45a124613a2b98a32e35223e471686fefdbdccf71a
step() { echo "### $(date -u +%T) $*"; }
fail() { echo "!!! CHECK FAILED: $*"; bash "$B/rollback.sh"; exit 1; }

step "preconditions"
[ -f "$B/app.env.prod-6a3fcec" ] && [ -d /opt/link-detonator.prod-6a3fcec ] || { echo "no backup, nothing changed"; exit 1; }
[ "$(docker image inspect -f '{{.Id}}' "$IMAGE_ID" 2>/dev/null)" = "$IMAGE_ID" ] || { echo "release image missing, nothing changed"; exit 1; }
[ "$(find "$R" -type f | wc -l)" -gt 100 ] || { echo "release tree missing, nothing changed"; exit 1; }
for _ in $(seq 60); do curl -s 127.0.0.1:8000/healthz | grep -q '"queued":0,"running":0' && break; sleep 2; done
curl -s 127.0.0.1:8000/healthz | grep -q '"queued":0,"running":0' || { echo "scans still running, nothing changed"; exit 1; }

step "stop app"
systemctl stop link-detonator.service

step "install code of cd875a3"
rsync -a --delete --exclude=/.venv --exclude=/data --exclude=__pycache__ "$R/" /opt/link-detonator/ || fail "rsync"
find /opt/link-detonator -path /opt/link-detonator/data -prune -o -exec chown -h root:root {} +
chmod 755 /opt/link-detonator /opt/link-detonator/deploy/firewall.sh /opt/link-detonator/deploy/verify_sandbox.sh /opt/link-detonator/deploy/provision.sh
diffs=$(cd "$R" && find . -type f | while read -r f; do cmp -s "$f" "/opt/link-detonator/$f" || echo "$f"; done | wc -l)
extra=$(cd /opt/link-detonator && find . -path ./.venv -prune -o -path ./data -prune -o -name __pycache__ -prune -o -type f -print | wc -l)
echo "  files: release $(find "$R" -type f | wc -l), deployed $extra, differing $diffs"
[ "$diffs" = 0 ] && [ "$extra" = "$(find "$R" -type f | wc -l)" ] || fail "deployed code differs from cd875a3"

step "settings: pin image by ID, browser under gVisor"
tmp=$(mktemp); grep -vE '^(LD_IMAGE|LD_RUNTIME|LD_SANDBOX_RESOLV_CONF|LD_CHROMIUM_SANDBOX)=' "$ENV" >"$tmp"
printf '%s\n' "LD_IMAGE=$IMAGE_ID" LD_RUNTIME=runsc LD_SANDBOX_RESOLV_CONF=/etc/link-detonator/sandbox-resolv.conf LD_CHROMIUM_SANDBOX=1 >>"$tmp"
cat "$tmp" >"$ENV"; rm -f "$tmp"   # keeps the file's owner and mode
echo "  app.env $(stat -c '%a %U:%G' "$ENV"); release keys: $(grep -E '^LD_(IMAGE|RUNTIME|DECODER_RUNTIME|SANDBOX_RESOLV_CONF|CHROMIUM_SANDBOX)=' "$ENV" | tr '\n' ' ')"
echo "  other keys unchanged: $(diff <(grep -vE '^(LD_IMAGE|LD_RUNTIME|LD_SANDBOX_RESOLV_CONF|LD_CHROMIUM_SANDBOX)=' "$ENV") <(grep -vE '^(LD_IMAGE|LD_RUNTIME|LD_SANDBOX_RESOLV_CONF|LD_CHROMIUM_SANDBOX)=' "$B/app.env.prod-6a3fcec") >/dev/null && echo yes || echo NO)"

step "firewall check"
/opt/link-detonator/deploy/firewall.sh --check || fail "firewall.sh --check"

step "verify_sandbox.sh (app stopped, settings from app.env)"
out=$(/opt/link-detonator/deploy/verify_sandbox.sh 2>&1); echo "$out" >/root/release/verify-sandbox-postdeploy.txt
echo "$out" | head -4; echo "$out" | tail -1
echo "$out" | grep -q "^Image: $IMAGE_ID" || fail "verifier did not test the release image"
echo "$out" | tail -1 | grep -qx "44 passed, 0 failed" || fail "verify_sandbox"

step "start app"
systemctl start link-detonator.service
ok=0; for _ in $(seq 30); do curl -sf 127.0.0.1:8000/healthz >/dev/null && ok=1 && break; sleep 1; done
[ "$ok" = 1 ] || fail "health"
echo "  health: $(curl -s 127.0.0.1:8000/healthz)"
pid=$(systemctl show -p MainPID --value link-detonator.service)
echo "  running process settings: $(tr '\0' '\n' </proc/$pid/environ | grep -E '^LD_(IMAGE|RUNTIME|DECODER_RUNTIME|SANDBOX_RESOLV_CONF|CHROMIUM_SANDBOX)=' | sort | tr '\n' ' ')"
tr '\0' '\n' </proc/$pid/environ | grep -qx "LD_IMAGE=$IMAGE_ID" || fail "running app not pinned to the release image"
step "deploy phase done; external checks next"
