# shellcheck shell=bash
# Shared constants and helpers, sourced by the other deploy scripts.
# Network values mirror docs/CONTRACT.md; change them there first.

# shellcheck disable=SC2034  # used by the scripts that source this file
{
  LD_APP_DIR=/opt/link-detonator
  LD_ENV_FILE=/etc/link-detonator/app.env
  LD_SANDBOX_NETWORK=ld-sandbox
  LD_SANDBOX_BRIDGE=ld-br0
  LD_SANDBOX_SUBNET=172.30.0.0/24
  LD_SANDBOX_GATEWAY=172.30.0.1
  LD_EGRESS_CHAIN=LD-SANDBOX-EGRESS
  LD_INPUT_CHAIN=LD-SANDBOX-INPUT
}

# The only resolvers the sandbox may reach. Written to /etc/docker/daemon.json by
# provision.sh and allowed by firewall.sh. They must not filter by reputation:
# a resolver that hides known-bad domains would hide what a scan is meant to see.
LD_SANDBOX_DNS="${LD_SANDBOX_DNS:-1.1.1.1 8.8.8.8}"

log() { printf '[%s] %s\n' "$(basename "$0")" "$*"; }
die() {
  printf '[%s] ERROR: %s\n' "$(basename "$0")" "$*" >&2
  exit 1
}

require_root() {
  [[ "$(id -u)" -eq 0 ]] || die "must run as root"
}

# Prints KEY's value from the env file, or nothing. The file is parsed rather than
# sourced so that a root shell never executes its contents.
env_file_value() {
  local key=$1
  [[ -r "$LD_ENV_FILE" ]] || return 0
  awk -F= -v key="$key" '$1 == key { sub(/^[^=]*=/, ""); value = $0 } END { print value }' "$LD_ENV_FILE"
}

# The address the VM uses to reach the internet. On a standard Vultr instance this is
# the public IP, assigned directly to the NIC. LD_PUBLIC_IP overrides it.
public_ip() {
  if [[ -n "${LD_PUBLIC_IP:-}" ]]; then
    printf '%s\n' "$LD_PUBLIC_IP"
    return 0
  fi
  ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p'
}
