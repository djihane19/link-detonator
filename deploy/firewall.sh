#!/usr/bin/env bash
# Applies the sandbox network policy from docs/CONTRACT.md. Safe to re-run.
#
#   firewall.sh           apply the rules (root, after docker.service)
#   firewall.sh --check   change nothing; exit non-zero if the policy is not in place
#   firewall.sh --print-rules   print the chain rules; needs no root and changes nothing
#
# Two decisions behind that policy, explained in docs/ARCHITECTURE.md ("Firewall decisions"):
#   1. Blocked traffic is REJECTed rather than silently dropped.
#   2. DNS is allowed to the pinned resolvers only.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/common.sh
. "$SCRIPT_DIR/common.sh"

BLOCKED_CIDRS="169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 127.0.0.0/8 0.0.0.0/8 224.0.0.0/4 240.0.0.0/4"

# To get a literal silent drop, set this to "DROP". verify_sandbox.sh accepts either,
# but a dropped SYN hangs Chromium past the scan deadline, so request_failed never fires.
BLOCK_TARGET="REJECT --reject-with icmp-admin-prohibited"

# Scanned pages run a stranger's JavaScript from this VM's address. These bound how much
# of a flood or an upload can leave it. Measured from the sandbox, not per scan.
EGRESS_BYTES_LIMIT="2mb/s"
EGRESS_BYTES_BURST="8mb"
NEW_CONNECTIONS_PER_DEST="30/sec"
NEW_CONNECTIONS_BURST="60"
CONNECTIONS_PER_DEST="32"

EGRESS_JUMP="-i $LD_SANDBOX_BRIDGE -j $LD_EGRESS_CHAIN"
INPUT_JUMP="-i $LD_SANDBOX_BRIDGE -j $LD_INPUT_CHAIN"
V6_DROP="-i $LD_SANDBOX_BRIDGE -j DROP"
NETWORK_SIGNATURE="bridge|false|$LD_SANDBOX_SUBNET|$LD_SANDBOX_BRIDGE|false"

ipt() { iptables -w 10 "$@"; }

# One rulespec per line, in evaluation order. RETURN hands the packet back to Docker's
# own FORWARD rules rather than accepting it outright, so they still apply.
egress_rules() {
  local cidr resolver
  # Before the ESTABLISHED rule, because an upload is established traffic.
  printf '%s\n' "-m hashlimit --hashlimit-above $EGRESS_BYTES_LIMIT --hashlimit-burst $EGRESS_BYTES_BURST --hashlimit-mode srcip --hashlimit-name ld-egress-bytes -j DROP"
  printf '%s\n' "-m conntrack --ctstate ESTABLISHED -j RETURN"
  for cidr in $BLOCKED_CIDRS; do
    printf '%s\n' "-d $cidr -j $BLOCK_TARGET"
  done
  for resolver in $LD_SANDBOX_DNS; do
    printf '%s\n' "-d $resolver/32 -p udp -m udp --dport 53 -j RETURN"
    printf '%s\n' "-d $resolver/32 -p tcp -m tcp --dport 53 -j RETURN"
  done
  # After the private ranges, so a private destination always gets the plain rejection.
  printf '%s\n' "-p tcp -m tcp --syn -m connlimit --connlimit-above $CONNECTIONS_PER_DEST --connlimit-mask 32 --connlimit-daddr -j $BLOCK_TARGET"
  printf '%s\n' "-p tcp -m tcp --syn -m hashlimit --hashlimit-above $NEW_CONNECTIONS_PER_DEST --hashlimit-burst $NEW_CONNECTIONS_BURST --hashlimit-mode dstip --hashlimit-name ld-new-conns -j $BLOCK_TARGET"
  printf '%s\n' "-p tcp -m tcp --dport 80 -j RETURN"
  printf '%s\n' "-p tcp -m tcp --dport 443 -j RETURN"
  printf '%s\n' "-j $BLOCK_TARGET"
}

# INPUT is separate because DOCKER-USER only sees forwarded traffic. Without this, a
# container could reach the VM's own services, including through its public IP.
input_rules() {
  printf '%s\n' "-j $BLOCK_TARGET"
}

# Replaces both chains in one transaction, so a re-run never leaves them empty or partial.
load_chains() {
  {
    printf '*filter\n'
    printf ':%s - [0:0]\n' "$LD_EGRESS_CHAIN" "$LD_INPUT_CHAIN"
    egress_rules | sed "s/^/-A $LD_EGRESS_CHAIN /"
    input_rules | sed "s/^/-A $LD_INPUT_CHAIN /"
    printf 'COMMIT\n'
  } | iptables-restore -w 10 --noflush
}

# Makes `spec` the first rule of a chain, exactly once. The new copy goes in before any
# old copy comes out, so the rule is never absent. Needed because ufw and others may
# have rules in the same chain; ours must be evaluated before ufw's port allows.
ensure_first() {
  local tool=$1 chain=$2 spec=$3 positions position
  local -a args
  read -r -a args <<<"$spec"
  positions=$("$tool" -w 10 -S "$chain" | awk -v want="-A $chain $spec" '$0 == want { print NR - 1 }')
  [[ "$positions" == "1" ]] && return 0
  "$tool" -w 10 -I "$chain" 1 "${args[@]}"
  # Highest first so the earlier numbers stay valid; +1 accounts for the new copy.
  for position in $(printf '%s\n' "$positions" | sort -rn); do
    "$tool" -w 10 -D "$chain" "$((position + 1))"
  done
}

network_signature() {
  docker network inspect "$LD_SANDBOX_NETWORK" --format \
    '{{.Driver}}|{{.EnableIPv6}}|{{(index .IPAM.Config 0).Subnet}}|{{index .Options "com.docker.network.bridge.name"}}|{{index .Options "com.docker.network.bridge.enable_icc"}}' \
    2>/dev/null
}

ensure_network() {
  local current
  current=$(network_signature || true)
  [[ "$current" == "$NETWORK_SIGNATURE" ]] && return 0
  if [[ -n "$current" ]]; then
    log "network $LD_SANDBOX_NETWORK differs from the contract ($current); recreating"
    docker network rm "$LD_SANDBOX_NETWORK" >/dev/null
  fi
  docker network create --driver bridge \
    --subnet "$LD_SANDBOX_SUBNET" --gateway "$LD_SANDBOX_GATEWAY" --ipv6=false \
    -o "com.docker.network.bridge.name=$LD_SANDBOX_BRIDGE" \
    -o com.docker.network.bridge.enable_icc=false \
    "$LD_SANDBOX_NETWORK" >/dev/null
  log "created network $LD_SANDBOX_NETWORK"
}

# enable_icc=false relies on bridged traffic passing through iptables.
ensure_bridge_netfilter() {
  modprobe br_netfilter 2>/dev/null || log "could not load br_netfilter; continuing"
  if [[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ]]; then
    sysctl -q -w net.bridge.bridge-nf-call-iptables=1
  fi
}

ip6tables_usable() {
  command -v ip6tables >/dev/null 2>&1 && ip6tables -w 10 -S INPUT >/dev/null 2>&1
}

# The network has IPv6 off. These cover a link-local path to the host anyway.
apply_ipv6_block() {
  if [[ -e "/proc/sys/net/ipv6/conf/$LD_SANDBOX_BRIDGE/disable_ipv6" ]]; then
    sysctl -q -w "net.ipv6.conf.$LD_SANDBOX_BRIDGE.disable_ipv6=1"
  fi
  if ip6tables_usable; then
    ensure_first ip6tables INPUT "$V6_DROP"
    ensure_first ip6tables FORWARD "$V6_DROP"
  fi
}

apply() {
  require_root
  ipt -S DOCKER-USER >/dev/null 2>&1 \
    || die "DOCKER-USER chain missing; dockerd must be running with iptables enabled"

  # Rules first, network second: the rules match the bridge by name, so the bridge
  # never exists without them.
  ensure_bridge_netfilter
  load_chains
  ensure_first iptables DOCKER-USER "$EGRESS_JUMP"
  ensure_first iptables INPUT "$INPUT_JUMP"
  # ufw's forward chains accept ICMP echo, so they must not run before DOCKER-USER.
  ensure_first iptables FORWARD "-j DOCKER-USER"
  ensure_network
  apply_ipv6_block
  log "sandbox firewall applied"
}

check_first() {
  local chain=$1 spec=$2
  if [[ "$(ipt -S "$chain" 1 2>/dev/null)" != "-A $chain $spec" ]]; then
    printf 'missing: %s must start with: %s\n' "$chain" "$spec" >&2
    return 1
  fi
}

# Confirms a chain holds exactly the expected rules, and no others.
check_chain() {
  local chain=$1 rules=$2 expected actual status=0 spec
  local -a args
  while IFS= read -r spec; do
    read -r -a args <<<"$spec"
    if ! ipt -C "$chain" "${args[@]}" 2>/dev/null; then
      printf 'missing: %s %s\n' "$chain" "$spec" >&2
      status=1
    fi
  done <<<"$rules"
  expected=$(printf '%s\n' "$rules" | wc -l | tr -d ' ')
  actual=$(ipt -S "$chain" 2>/dev/null | grep -c '^-A ' || true)
  if [[ "$actual" != "$expected" ]]; then
    printf 'wrong rule count in %s: expected %s, found %s\n' "$chain" "$expected" "$actual" >&2
    status=1
  fi
  return "$status"
}

check() {
  require_root
  local status=0 current
  local -a v6_args
  read -r -a v6_args <<<"$V6_DROP"
  check_chain "$LD_EGRESS_CHAIN" "$(egress_rules)" || status=1
  check_chain "$LD_INPUT_CHAIN" "$(input_rules)" || status=1
  check_first DOCKER-USER "$EGRESS_JUMP" || status=1
  check_first INPUT "$INPUT_JUMP" || status=1
  check_first FORWARD "-j DOCKER-USER" || status=1
  current=$(network_signature || true)
  if [[ "$current" != "$NETWORK_SIGNATURE" ]]; then
    printf 'network mismatch: expected %s, found %s\n' "$NETWORK_SIGNATURE" "${current:-nothing}" >&2
    status=1
  fi
  if ip6tables_usable; then
    ip6tables -w 10 -C INPUT "${v6_args[@]}" 2>/dev/null || { echo 'missing: ip6tables INPUT drop' >&2; status=1; }
    ip6tables -w 10 -C FORWARD "${v6_args[@]}" 2>/dev/null || { echo 'missing: ip6tables FORWARD drop' >&2; status=1; }
  fi
  if [[ "$status" -eq 0 ]]; then
    log "sandbox firewall in place"
  fi
  return "$status"
}

case "${1:-}" in
  "") apply ;;
  --check) check ;;
  --print-rules)
    egress_rules
    input_rules
    ;;
  *) die "usage: firewall.sh [--check | --print-rules]" ;;
esac
