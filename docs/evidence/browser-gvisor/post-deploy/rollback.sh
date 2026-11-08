#!/usr/bin/env bash
# Documented rollback: restores code, complete app.env and image reference, then verifies.
set -uo pipefail
B=/root/release-backup-20261108
ENV=/etc/link-detonator/app.env
OLD_ID=sha256:ae0a280682e49ba002a680db8300438ecf0ac65ee1a382bc8c1eecf3daf35fc6
echo "### ROLLBACK $(date -u +%FT%TZ)"
systemctl stop link-detonator.service
rsync -a --delete --exclude=/data /opt/link-detonator.prod-6a3fcec/ /opt/link-detonator/
cp -p "$B/app.env.prod-6a3fcec" "$ENV"
docker tag link-detonator-worker:prod-6a3fcec link-detonator-worker:latest
fail=0
[ "$(rsync -ani --delete --exclude=/data /opt/link-detonator.prod-6a3fcec/ /opt/link-detonator/ | wc -l)" = 0 ] && echo "  code restored" || { echo "  CODE NOT RESTORED"; fail=1; }
cmp -s "$ENV" "$B/app.env.prod-6a3fcec" && echo "  app.env restored (runtime settings as before)" || { echo "  APP.ENV NOT RESTORED"; fail=1; }
[ "$(docker image inspect -f '{{.Id}}' link-detonator-worker:latest)" = "$OLD_ID" ] && echo "  :latest = previous image" || { echo "  IMAGE NOT RESTORED"; fail=1; }
/opt/link-detonator/deploy/verify_sandbox.sh | tail -1
systemctl start link-detonator.service
for _ in $(seq 30); do curl -sf 127.0.0.1:8000/healthz && break; sleep 1; done; echo
exit $fail
