#!/usr/bin/env bash
# Proves the sandbox policy on the VM: starts containers with the exact flags the app
# uses and prints PASS or FAIL for each check. Exits non-zero on any FAIL.
#
# A failed connection alone is not proof, since nothing may be listening there. Blocked
# checks therefore also require the matching firewall rule's packet counter to rise, so
# run this while no scans are in progress.
#
# Run as root on the VM. It makes real outbound requests: only ever run it there.
#   VERIFY_HOST            public name used for the DNS and HTTPS checks (example.com)
#   VERIFY_OTHER_RESOLVER  a public resolver not in LD_SANDBOX_DNS (9.9.9.9)
#   LD_IMAGE               image to test (same variable the app reads)
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/common.sh
. "$SCRIPT_DIR/common.sh"

VERIFY_HOST="${VERIFY_HOST:-example.com}"
VERIFY_OTHER_RESOLVER="${VERIFY_OTHER_RESOLVER:-9.9.9.9}"
IMAGE="${LD_IMAGE:-$(env_file_value LD_IMAGE)}"
IMAGE="${IMAGE:-link-detonator-worker:latest}"
RUNTIME="${LD_RUNTIME:-$(env_file_value LD_RUNTIME)}"
# The QR and email decoders may use a different runtime (gVisor) from the browser sandbox.
DECODER_RUNTIME="${LD_DECODER_RUNTIME:-$(env_file_value LD_DECODER_RUNTIME)}"
# Browser under gVisor: the pinned resolver file and Chromium's own sandbox (see app/config.py).
RESOLV_CONF="${LD_SANDBOX_RESOLV_CONF:-$(env_file_value LD_SANDBOX_RESOLV_CONF)}"
CHROMIUM_SANDBOX="${LD_CHROMIUM_SANDBOX:-$(env_file_value LD_CHROMIUM_SANDBOX)}"
PROBE_SOURCE=$(cat "$SCRIPT_DIR/sandbox_probe.py")

# Checks the contract requires. Each must report at least once, or it counts as a FAIL;
# a probe that crashes part-way must not read as a clean run.
REQUIRED_CHECKS="metadata blocked|RFC1918 blocked|host gateway blocked|public-IP blocked|public HTTPS allowed|DNS works|rootfs read-only|/tmp noexec|no capabilities|non-root|no env secrets|pid limit|memory limit|connection cap per destination|browser sees the firewall error|no private answers|live page loads|docker kill stops the sandbox|decoder has no network"

passes=0
failures=0
seen=""
container_seq=0
container_name=""
long_running=""

report() {
  local status=$1 check=$2 detail=$3
  printf '%-4s  %-24s  %s\n' "$status" "$check" "$detail"
  seen="$seen|$check|"
  if [[ "$status" == "PASS" ]]; then
    passes=$((passes + 1))
  else
    failures=$((failures + 1))
  fi
}

cleanup() {
  if [[ -n "$long_running" ]]; then
    docker rm -f "$long_running" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Called in this shell, not in $(...), so the sequence number survives.
next_container_name() {
  container_seq=$((container_seq + 1))
  container_name="ld-verify-$$-$container_seq"
}

# Keep this list identical to build_docker_argv in app/sandbox.py.
sandbox_run() {
  local name=$1
  shift
  local -a flags=(
    --rm --init --name "$name" --label link-detonator=1 --network "$LD_SANDBOX_NETWORK"
    --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m
    --cap-drop ALL --security-opt no-new-privileges
    --pids-limit 256 --memory 1g --memory-swap 1g --cpus 1 --shm-size 128m
    --ulimit nofile=1024:1024 --log-driver none --user pwuser
  )
  if [[ -n "$RUNTIME" ]]; then
    flags+=(--runtime "$RUNTIME")
  fi
  if [[ -n "$RESOLV_CONF" ]]; then
    flags+=(--mount "type=bind,source=$RESOLV_CONF,target=/etc/resolv.conf,readonly")
  fi
  docker run "${flags[@]}" "$@"
}

chromium_flag() {
  [[ "$CHROMIUM_SANDBOX" == "1" || "$CHROMIUM_SANDBOX" == "true" ]] && printf -- '--chromium-sandbox'
}

# Runs one probe command in its own container and reports each line it prints.
run_probe() {
  local command=$1 output status_code=0 status check detail
  shift
  next_container_name
  output=$(sandbox_run "$container_name" "$IMAGE" python -c "$PROBE_SOURCE" "$command" "$@" 2>&1) || status_code=$?
  while IFS=$'\t' read -r status check detail; do
    case "$status" in
      PASS | FAIL) report "$status" "$check" "$detail" ;;
      "") ;;
      *) report FAIL "probe $command" "unexpected output: $status" ;;
    esac
  done <<<"$output"
  if [[ "$status_code" -ne 0 ]]; then
    report FAIL "probe $command" "container exited $status_code"
  fi
}

# Packets counted by the rule in `chain` whose destination is `dest`. "last" means the
# chain's final rule, whose source and destination are both 0.0.0.0/0.
rule_hits() {
  local chain=$1 dest=$2
  if [[ "$dest" == "last" ]]; then
    iptables -w 10 -L "$chain" -v -n -x | tail -n 1 | awk '{ print $1 }'
    return 0
  fi
  iptables -w 10 -L "$chain" -v -n -x | awk -v dest="$dest" '
    { for (i = 4; i <= NF; i++) if ($i == dest) { hits = $1 } }
    END { print hits + 0 }'
}

COUNTED_RULES="
metadata|$LD_EGRESS_CHAIN|169.254.0.0/16
RFC1918 10/8|$LD_EGRESS_CHAIN|10.0.0.0/8
RFC1918 172.16/12|$LD_EGRESS_CHAIN|172.16.0.0/12
RFC1918 192.168/16|$LD_EGRESS_CHAIN|192.168.0.0/16
CGNAT|$LD_EGRESS_CHAIN|100.64.0.0/10
other ports|$LD_EGRESS_CHAIN|last
host and public IP|$LD_INPUT_CHAIN|last
"

snapshot_counters() {
  local label chain dest
  while IFS='|' read -r label chain dest; do
    [[ -n "$label" ]] || continue
    printf '%s|%s\n' "$label" "$(rule_hits "$chain" "$dest")"
  done <<<"$COUNTED_RULES"
}

report_counter_growth() {
  local before=$1 label chain dest was now
  while IFS='|' read -r label chain dest; do
    [[ -n "$label" ]] || continue
    was=$(printf '%s\n' "$before" | awk -F'|' -v label="$label" '$1 == label { print $2 }')
    now=$(rule_hits "$chain" "$dest")
    if [[ "$now" -gt "$was" ]]; then
      report PASS "firewall rule hit" "$label: $was -> $now packets"
    else
      report FAIL "firewall rule hit" "$label: stayed at $now; the failure did not come from this rule"
    fi
  done <<<"$COUNTED_RULES"
}

# Compares inside this process so that secret values never reach argv, logs or output.
check_secrets_absent() {
  local name=$1 container_env key value compared=0 leaked=0
  container_env=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$name")

  # The canary proves the check still works on a VM with no secrets configured yet.
  compared=$((compared + 1))
  if [[ "$container_env" == *"$VERIFY_CANARY"* ]]; then
    leaked=$((leaked + 1))
  fi

  if [[ -r "$LD_ENV_FILE" ]]; then
    while IFS='=' read -r key value; do
      [[ "$key" =~ (KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|ACCESS_CODE) ]] || continue
      [[ -n "$value" ]] || continue
      compared=$((compared + 1))
      if [[ "$container_env" == *"$value"* ]]; then
        leaked=$((leaked + 1))
      fi
    done <"$LD_ENV_FILE"
  fi

  if [[ "$leaked" -eq 0 ]]; then
    report PASS "no env secrets" "Config.Env holds none of $compared compared value(s)"
  else
    report FAIL "no env secrets" "$leaked of $compared compared value(s) found in Config.Env"
  fi
}

check_running_container() {
  # The canary sits in the docker CLI's environment. Nothing should carry it across.
  VERIFY_CANARY="ld-canary-$$-$RANDOM$RANDOM"
  export VERIFY_CANARY
  next_container_name
  long_running=$container_name
  if ! sandbox_run "$container_name" -d "$IMAGE" python -c 'import time; time.sleep(120)' >/dev/null 2>&1; then
    report FAIL "no env secrets" "could not start the inspection container"
    long_running=""
    return 0
  fi
  check_secrets_absent "$long_running"

  # Allowed: nothing, or exactly the configured resolver file, read-only, at /etc/resolv.conf.
  local mounts expected=""
  mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}}>{{.Destination}}>{{.RW}};{{end}}' "$long_running")
  [[ -n "$RESOLV_CONF" ]] && expected="$RESOLV_CONF>/etc/resolv.conf>false;"
  if [[ "$mounts" == "$expected" ]]; then
    report PASS "no mounts" "${expected:+only the read-only resolver file }(${mounts:-0 mounts})"
  else
    report FAIL "no mounts" "unexpected mounts: ${mounts:-none} (expected ${expected:-none})"
  fi
  check_docker_kill "$long_running"
  docker rm -f "$long_running" >/dev/null 2>&1 || true
  long_running=""
}

# The report's kill_confirmed relies on docker kill succeeding and the container then
# not running. --rm usually makes it vanish, so "no such container" also counts.
check_docker_kill() {
  local name=$1 running
  if ! docker kill "$name" >/dev/null 2>&1; then
    report FAIL "docker kill stops the sandbox" "docker kill returned non-zero"
    return 0
  fi
  # docker kill returns once the signal is sent; allow the same bounded 3 s the app allows.
  local attempt
  for attempt in $(seq 1 30); do
    # A missing container counts as stopped. Docker 29 prints an empty line before its
    # "no such object" error, so judge by the exit status, never by mixed output.
    if ! running=$(docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null); then
      running=false
    fi
    [[ "$running" == "false" ]] && break
    sleep 0.1
  done
  if [[ "$running" == "false" ]]; then
    report PASS "docker kill stops the sandbox" "not running $((attempt * 100)) ms after docker kill"
  else
    report FAIL "docker kill stops the sandbox" "still running 3 s after docker kill"
  fi
}

# gVisor ends the whole sandbox at its limits instead of returning EAGAIN or killing one
# process, so its pid and memory limits are judged from host facts: the container must end
# before passing the limit, never reach it unrefused, and (for memory) be OOM-killed.
check_gvisor_limits() {
  local name output code oom last limit
  next_container_name; name=$container_name
  output=$(sandbox_run "$name" "$IMAGE" python -u -c '
import os, time
for n in range(1, 400):
    if os.fork() == 0:
        time.sleep(30); os._exit(0)
    print(n, flush=True)
print("NEVER-REFUSED", flush=True)' 2>/dev/null) && code=0 || code=$?
  last=$(printf '%s\n' "$output" | grep -E '^[0-9]+$' | tail -1)
  if [[ "$output" != *NEVER-REFUSED* && "$code" -ne 0 && -n "$last" && "$last" -lt 256 ]]; then
    report PASS "pid limit" "gVisor sandbox ended after $last guest processes (pids-limit 256, exit $code)"
  else
    report FAIL "pid limit" "exit $code after ${last:-0} processes, never refused: $([[ "$output" == *NEVER-REFUSED* ]] && echo yes || echo no)"
  fi
  next_container_name; name=$container_name
  local -a flags=(
    --init --name "$name" --label link-detonator=1 --network "$LD_SANDBOX_NETWORK"
    --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m --cap-drop ALL --security-opt no-new-privileges
    --pids-limit 256 --memory 1g --memory-swap 1g --cpus 1 --user pwuser --runtime "$RUNTIME"
  )
  long_running=$name
  output=$(docker run "${flags[@]}" "$IMAGE" python -u -c '
blocks = []
for n in range(1, 64):
    block = bytearray(32 * 1024 * 1024); block[::4096] = b"\x01" * len(range(0, len(block), 4096)); blocks.append(block)
    print(n * 32, flush=True)
print("NOT-KILLED", flush=True)' 2>/dev/null) && code=0 || code=$?
  oom=$(docker inspect --format '{{.State.OOMKilled}}' "$name" 2>/dev/null || echo unknown)
  limit=$(docker inspect --format '{{.HostConfig.Memory}}' "$name" 2>/dev/null || echo unknown)
  docker rm -f "$name" >/dev/null 2>&1 || true; long_running=""
  last=$(printf '%s\n' "$output" | grep -E '^[0-9]+$' | tail -1)
  if [[ "$oom" == "true" && "$output" != *NOT-KILLED* && -n "$last" && "$last" -le 1024 && "$limit" == "1073741824" ]]; then
    report PASS "memory limit" "gVisor sandbox OOM-killed by the host after ${last} MiB (memory limit $limit, exit $code)"
  else
    report FAIL "memory limit" "OOMKilled=$oom, reached ${last:-0} MiB, limit $limit, exit $code"
  fi
}

check_browser_runtime() {
  local kernel
  next_container_name
  kernel=$(sandbox_run "$container_name" "$IMAGE" python -c 'import platform; print(platform.release())' 2>/dev/null || true)
  if [[ "$kernel" == *gvisor* ]]; then
    report PASS "browser runs under gVisor" "kernel seen inside: $kernel"
  else
    report FAIL "browser runs under gVisor" "kernel seen inside: ${kernel:-none}"
  fi
}

# The file decoders run with no network and, when configured, under gVisor. Same flags as
# app/qr.py build_decoder_argv; the image arrives on stdin, so there is nothing to mount.
check_decoder_sandbox() {
  local name output kernel network uid
  next_container_name
  name=$container_name
  local -a flags=(
    --rm --init -i --name "$name" --label link-detonator=1 --network none --read-only
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --cap-drop ALL --security-opt no-new-privileges
    --pids-limit 64 --memory 256m --memory-swap 256m --cpus 1 --ulimit nofile=256:256
    --log-driver none --user pwuser
  )
  if [[ -n "$DECODER_RUNTIME" ]]; then
    flags+=(--runtime "$DECODER_RUNTIME")
  fi
  output=$(docker run "${flags[@]}" "$IMAGE" python -c '
import os, platform, socket
s = socket.socket(); s.settimeout(3)
try:
    s.connect(("1.1.1.1", 443)); net = "reachable"
except OSError as exc:
    net = type(exc).__name__ + ":" + str(exc.errno)
print(platform.release(), net, os.getuid(), sep="\t")
' </dev/null 2>/dev/null || true)
  IFS=$'\t' read -r kernel network uid <<<"$output"
  if [[ -n "$network" && "$network" != "reachable" && -n "$uid" && "$uid" != "0" ]]; then
    report PASS "decoder has no network" "connect -> $network, uid=$uid"
  else
    report FAIL "decoder has no network" "output: ${output:-none}"
  fi
  if [[ "$DECODER_RUNTIME" == "runsc" ]]; then
    if [[ "$kernel" == *gvisor* ]]; then
      report PASS "decoder runs under gVisor" "kernel seen inside: $kernel"
    else
      report FAIL "decoder runs under gVisor" "kernel seen inside: ${kernel:-none}"
    fi
  fi
}

# Runs the real worker under the real flags and judges its events. This is what measures
# the error string the private_network row relies on (FIREWALL_REJECT_ERRORS).
run_worker_check() {
  local check=$1 status check_name detail output
  shift
  next_container_name
  output=$(sandbox_run "$container_name" "$IMAGE" python /worker/worker.py "$@" --deadline 40 $(chromium_flag) 2>/dev/null || true)
  while IFS=$'\t' read -r status check_name detail; do
    case "$status" in
      PASS | FAIL) report "$status" "$check_name" "$detail" ;;
      "") ;;
      *) report FAIL "worker check $check" "unexpected output: $status" ;;
    esac
  done < <(printf '%s\n' "$output" | python3 "$SCRIPT_DIR/check_worker_events.py" "$check")
}

check_required_reported() {
  local required
  while IFS= read -r required; do
    case "$seen" in
      *"|$required|"*) ;;
      *) report FAIL "$required" "no result: the probe did not report this check" ;;
    esac
  done <<<"$(printf '%s\n' "$REQUIRED_CHECKS" | tr '|' '\n')"
}

main() {
  require_root
  docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || die "image $IMAGE not found; run 'make worker-image' first"

  local host_ip first_resolver before
  host_ip=$(public_ip)
  [[ -n "$host_ip" ]] || die "could not determine the public IP; set LD_PUBLIC_IP"
  first_resolver=${LD_SANDBOX_DNS%% *}

  printf 'Image: %s\nRuntime: %s\nDecoder runtime: %s\nPublic IP: %s\n\n' "$IMAGE" "${RUNTIME:-default}" "${DECODER_RUNTIME:-default}" "$host_ip"

  if "$SCRIPT_DIR/firewall.sh" --check >/dev/null 2>&1; then
    report PASS "firewall rules present" "firewall.sh --check"
  else
    report FAIL "firewall rules present" "run deploy/firewall.sh --check for details"
  fi

  before=$(snapshot_counters)
  run_probe network "$host_ip" "$LD_SANDBOX_GATEWAY" "$first_resolver" "$VERIFY_OTHER_RESOLVER" "$VERIFY_HOST"
  report_counter_growth "$before"

  run_worker_check private-network --fixture hostile-ssrf
  run_worker_check live-page --url "https://$VERIFY_HOST/"

  run_probe filesystem
  run_probe identity
  if [[ "$RUNTIME" == "runsc" ]]; then
    check_browser_runtime
    check_gvisor_limits
    if [[ -n "$(chromium_flag)" ]]; then
      run_probe chromium-sandbox "https://$VERIFY_HOST/"
    fi
  else
    run_probe pids
    run_probe memory
  fi
  check_running_container
  check_decoder_sandbox
  check_required_reported

  printf '\n%s passed, %s failed\n' "$passes" "$failures"
  [[ "$failures" -eq 0 ]]
}

main "$@"
