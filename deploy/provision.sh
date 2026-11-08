#!/usr/bin/env bash
# Provisions a fresh Ubuntu 24.04 VM. Safe to re-run. Run as root, with the repo at
# /opt/link-detonator. This VM must hold nothing else: see README, "Security model".
#
# The app and the public proxy start only after verify_sandbox.sh passes.
#   LD_SITE_ADDRESS  public name for Caddy (<public-ip>.sslip.io). Pass it on every run.
#   LD_PUBLIC_IP     override public IP detection
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/common.sh
. "$SCRIPT_DIR/common.sh"

SERVICE_USER=detonator
DOCKER_CONFIG_FILE=/etc/docker/daemon.json

preflight() {
  require_root
  [[ "$SCRIPT_DIR" == "$LD_APP_DIR/deploy" ]] \
    || die "the repo must be at $LD_APP_DIR (this script is in $SCRIPT_DIR)"
  [[ -f "$LD_APP_DIR/worker/Dockerfile" ]] || die "worker/Dockerfile not found in $LD_APP_DIR"
  [[ -f "$LD_APP_DIR/requirements.txt" ]] || die "requirements.txt not found in $LD_APP_DIR"
  local version
  # shellcheck disable=SC1091  # present on the target, not at lint time
  version=$(. /etc/os-release && printf '%s %s' "$ID" "$VERSION_ID")
  [[ "$version" == "ubuntu 24.04" ]] || log "warning: written for ubuntu 24.04, found $version"
}

install_packages() {
  log "installing packages"
  export DEBIAN_FRONTEND=noninteractive
  # Fresh images may still be running cloud-init or unattended-upgrades.
  apt-get -o DPkg::Lock::Timeout=300 update -q
  apt-get -o DPkg::Lock::Timeout=300 install -y -q \
    docker.io caddy iptables ufw python3-venv iproute2 make
}

create_user_and_dirs() {
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /var/lib/link-detonator --create-home \
      --shell /usr/sbin/nologin "$SERVICE_USER"
    log "created user $SERVICE_USER"
  fi
  usermod -aG docker "$SERVICE_USER"

  # The service user can write its data, but not its own code. data/ is skipped so a
  # re-run does not take existing scans away from the service user.
  find "$LD_APP_DIR" -path "$LD_APP_DIR/data" -prune -o -exec chown -h root:root {} +
  chmod 755 "$LD_APP_DIR"
  chmod 755 "$LD_APP_DIR/deploy/firewall.sh" "$LD_APP_DIR/deploy/verify_sandbox.sh" "$LD_APP_DIR/deploy/provision.sh"
  install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 750 "$LD_APP_DIR/data"

  install -d -o root -g "$SERVICE_USER" -m 750 "$(dirname "$LD_ENV_FILE")"
  if [[ ! -f "$LD_ENV_FILE" ]]; then
    install -o root -g "$SERVICE_USER" -m 640 "$LD_APP_DIR/.env.example" "$LD_ENV_FILE"
    log "created $LD_ENV_FILE from .env.example"
  fi
  # Existing files are kept as they are, since they may hold secrets added later.
  grep -q '^LD_TRUST_PROXY=' "$LD_ENV_FILE" || printf 'LD_TRUST_PROXY=1\n' >>"$LD_ENV_FILE"
  sed -i 's/^LD_TRUST_PROXY=.*/LD_TRUST_PROXY=1/' "$LD_ENV_FILE"
  # With gVisor installed, the browser and the decoders run under it, and Chromium keeps
  # its own sandbox. Only missing keys are added, so an operator's explicit choice stays.
  if command -v runsc >/dev/null 2>&1; then
    local key
    for key in LD_RUNTIME=runsc LD_DECODER_RUNTIME=runsc \
      "LD_SANDBOX_RESOLV_CONF=$(dirname "$LD_ENV_FILE")/sandbox-resolv.conf" LD_CHROMIUM_SANDBOX=1; do
      grep -q "^${key%%=*}=" "$LD_ENV_FILE" || printf '%s\n' "$key" >>"$LD_ENV_FILE"
    done
  fi
}

# Docker's embedded resolver dials its upstream from inside the container's network
# namespace, so these are the addresses firewall.sh has to allow.
# gVisor (runsc) gives the file decoders their own user-space kernel. Installed from
# Google's signed apt repository; skipped with LD_INSTALL_GVISOR=0.
install_gvisor() {
  [[ "${LD_INSTALL_GVISOR:-1}" == "1" ]] || return 0
  if ! command -v runsc >/dev/null 2>&1; then
    log "installing gVisor (runsc)"
    curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
    printf 'deb [arch=%s signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main\n' \
      "$(dpkg --print-architecture)" >/etc/apt/sources.list.d/gvisor.list
    apt-get -o DPkg::Lock::Timeout=300 update -q
    apt-get -o DPkg::Lock::Timeout=300 install -y -q runsc
  fi
}

configure_docker() {
  local servers="" resolver desired runtimes=""
  for resolver in $LD_SANDBOX_DNS; do
    servers="$servers${servers:+, }\"$resolver\""
  done
  if command -v runsc >/dev/null 2>&1; then
    runtimes=$(printf ',\n  "runtimes": {\n    "runsc": {\n      "path": "%s"\n    }\n  }' "$(command -v runsc)")
  fi
  desired=$(printf '{\n  "dns": [%s]%s\n}' "$servers" "$runtimes")

  mkdir -p "$(dirname "$DOCKER_CONFIG_FILE")"
  if [[ ! -f "$DOCKER_CONFIG_FILE" || "$(cat "$DOCKER_CONFIG_FILE")" != "$desired" ]]; then
    if [[ -f "$DOCKER_CONFIG_FILE" ]]; then
      cp "$DOCKER_CONFIG_FILE" "$DOCKER_CONFIG_FILE.bak"
      log "replaced $DOCKER_CONFIG_FILE; the old one is at $DOCKER_CONFIG_FILE.bak"
    fi
    printf '%s\n' "$desired" >"$DOCKER_CONFIG_FILE"
    systemctl enable docker.service
    systemctl restart docker.service
  else
    systemctl enable --now docker.service
  fi
}

# gVisor's own network stack cannot reach Docker's embedded DNS (a NAT rule into the host
# network namespace's loopback), so a browser under runsc reads this file instead. It
# names the same resolvers firewall.sh allows, so DNS still crosses the egress rules. It is
# bind-mounted read-only only when LD_SANDBOX_RESOLV_CONF points at it.
write_sandbox_resolver() {
  local file resolver desired
  file="$(dirname "$LD_ENV_FILE")/sandbox-resolv.conf"
  desired="# Pinned resolvers for the browser sandbox under gVisor. Must match the DNS servers
# the firewall allows (LD_SANDBOX_DNS). Mounted read-only at /etc/resolv.conf."
  for resolver in $LD_SANDBOX_DNS; do
    desired=$(printf '%s\nnameserver %s' "$desired" "$resolver")
  done
  desired=$(printf '%s\noptions timeout:2 attempts:2' "$desired")
  if [[ ! -f "$file" || "$(cat "$file")" != "$desired" ]]; then
    printf '%s\n' "$desired" >"$file.tmp"
    chown root:root "$file.tmp"
    chmod 644 "$file.tmp"
    mv "$file.tmp" "$file"
    log "wrote $file"
  fi
}

install_app_venv() {
  log "installing the app into a virtualenv"
  python3 -m venv "$LD_APP_DIR/.venv"
  "$LD_APP_DIR/.venv/bin/pip" install --quiet --require-virtualenv -r "$LD_APP_DIR/requirements.txt"
}

# ufw comes first so that firewall.sh, which runs later, ends up ahead of its rules.
configure_ufw() {
  log "configuring ufw: allow 22, 80 and 443"
  ufw allow 22/tcp >/dev/null
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw --force enable >/dev/null
}

install_units() {
  install -m 644 "$LD_APP_DIR/deploy/link-detonator-firewall.service" /etc/systemd/system/
  install -m 644 "$LD_APP_DIR/deploy/link-detonator.service" /etc/systemd/system/
  systemctl daemon-reload
}

start_firewall() {
  systemctl enable link-detonator-firewall.service
  systemctl restart link-detonator-firewall.service
  "$LD_APP_DIR/deploy/firewall.sh" --check
}

build_worker_image() {
  log "building the worker image"
  make -C "$LD_APP_DIR" worker-image
}

verify() {
  log "verifying the sandbox"
  # Scans in progress would skew the rule counters this check relies on.
  # Disabled as well as stopped, so a failed run cannot come back at the next boot.
  systemctl disable --now link-detonator.service 2>/dev/null || true
  if ! "$LD_APP_DIR/deploy/verify_sandbox.sh"; then
    die "sandbox verification failed; the app is left stopped. Fix it and re-run."
  fi
}

start_app() {
  systemctl enable link-detonator.service
  systemctl restart link-detonator.service
}

configure_caddy() {
  local site="${LD_SITE_ADDRESS:-}" address rendered
  if [[ -z "$site" ]]; then
    address=$(public_ip)
    [[ -n "$address" ]] || die "could not determine the public IP; set LD_PUBLIC_IP or LD_SITE_ADDRESS"
    site="$address.sslip.io"
  fi
  [[ "$site" =~ ^[A-Za-z0-9.-]+$ ]] || die "invalid LD_SITE_ADDRESS: $site"

  rendered=$(mktemp)
  sed "s/__LD_SITE_ADDRESS__/$site/" "$LD_APP_DIR/deploy/Caddyfile" >"$rendered"
  if ! caddy validate --adapter caddyfile --config "$rendered"; then
    rm -f "$rendered"
    die "generated Caddyfile is invalid"
  fi
  install -m 644 "$rendered" /etc/caddy/Caddyfile
  rm -f "$rendered"
  systemctl enable caddy.service
  systemctl reload-or-restart caddy.service
  log "site address: https://$site/"
}

main() {
  preflight
  install_packages
  install_gvisor
  create_user_and_dirs
  configure_docker
  write_sandbox_resolver
  install_app_venv
  configure_ufw
  install_units
  start_firewall
  build_worker_image
  verify
  start_app
  configure_caddy
  if [[ -z "$(env_file_value LD_LIVE_ACCESS_CODE)" ]]; then
    log "live URL scans stay off until LD_LIVE_ACCESS_CODE is set in $LD_ENV_FILE; test charges work now"
  fi
  log "done. Re-check at any time, with no scans running: $LD_APP_DIR/deploy/verify_sandbox.sh"
}

main "$@"
