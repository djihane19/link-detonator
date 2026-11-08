#!/usr/bin/env bash
# Phase 0: preserve production before any change. Changes nothing in production.
set -euo pipefail
B=/root/release-backup-20261108
ENV=/etc/link-detonator/app.env
mkdir -p "$B"; chmod 700 "$B"
echo "### backup $(date -u +%FT%TZ)"
# 1. application files (code + virtualenv; scan data stays in place and is not touched)
rsync -a --delete --exclude=/data /opt/link-detonator/ /opt/link-detonator.prod-6a3fcec/
# 2. complete app.env, with owner and mode (contents never printed)
cp -p "$ENV" "$B/app.env.prod-6a3fcec"
# 3. image reference: the old app uses the default LD_IMAGE, link-detonator-worker:latest
OLD_ID=$(docker image inspect -f '{{.Id}}' link-detonator-worker:latest)
docker tag link-detonator-worker:latest link-detonator-worker:prod-6a3fcec
{
  echo "previous code commit: 6a3fcec (production files == its tracked files, checked)"
  echo "previous image ref: link-detonator-worker:latest (LD_IMAGE unset) = $OLD_ID"
  echo "previous image tag kept: link-detonator-worker:prod-6a3fcec = $(docker image inspect -f '{{.Id}}' link-detonator-worker:prod-6a3fcec)"
  echo "app.env sha256: $(sha256sum "$ENV" | cut -d' ' -f1)  mode/owner: $(stat -c '%a %U:%G' "$ENV")"
  echo "app.env keys: $(grep -v '^#' "$ENV" | cut -d= -f1 | grep . | sort | tr '\n' ' ')"
  echo "code copy: /opt/link-detonator.prod-6a3fcec ($(find /opt/link-detonator.prod-6a3fcec -type f | wc -l) files incl. .venv)"
} | tee "$B/manifest.txt"
echo "### rollback readiness (all must be empty or OK):"
echo "  code dry-run restore would change: $(rsync -ani --delete --exclude=/data /opt/link-detonator.prod-6a3fcec/ /opt/link-detonator/ | wc -l) entries"
cmp -s "$ENV" "$B/app.env.prod-6a3fcec" && echo "  app.env backup: identical, mode $(stat -c '%a %U:%G' "$B/app.env.prod-6a3fcec")"
[ "$(docker image inspect -f '{{.Id}}' link-detonator-worker:prod-6a3fcec)" = "$OLD_ID" ] && echo "  image tag prod-6a3fcec: OK"
