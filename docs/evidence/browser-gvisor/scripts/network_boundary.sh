#!/usr/bin/env bash
# Network-boundary test for the gVisor browser sandbox. Adds no firewall rule; proves it.
set -u
E=/root/gvisor-evidence
IMG=link-detonator-worker:candidate
F="--rm --init --network ld-sandbox --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 1g --memory-swap 1g --cpus 1 --shm-size 128m --ulimit nofile=1024:1024 --log-driver none --user pwuser --runtime runsc --mount type=bind,source=/etc/link-detonator/sandbox-resolv.conf,target=/etc/resolv.conf,readonly --label link-detonator=1 --label link-detonator.owner=nettest"
rules() { iptables-save | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]//'; }
counters() { iptables -L "$1" -v -x -n | awk 'NR>2 {printf "%s pkts  %s\n", $1, $0}' | cut -c1-150; }

echo "### $(date -u +%FT%TZ)  docker $(docker version -f '{{.Server.Version}}')  $(runsc --version | head -1)"
echo "### firewall before: iptables $(rules | sha256sum | cut -c1-16)  ip6tables $(ip6tables-save | grep -v '^#' | sed -E 's/\[[0-9]+:[0-9]+\]//' | sha256sum | cut -c1-16)"
rules >"$E/iptables-before.txt"
in0=$(iptables -L LD-SANDBOX-INPUT -v -x -n | awk 'NR==3{print $1}')
eg0=$(iptables -L LD-SANDBOX-EGRESS -v -x -n | awk '/reject-with/ && /0.0.0.0\/0 *$/{v=$1} END{print v}')

: >"$E/canary-listener.log"
setsid python3 "$E/canary_listener.py" 172.30.0.1 172.17.0.1 185.92.220.83 </dev/null >/dev/null 2>&1 &
LPID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do [ "$(ss -ltn | grep -c 18080)" = 3 ] && break; sleep 0.5; done
echo "### listener pid $LPID:"; ss -ltn | grep 18080
echo "### positive control from the host itself (the listener is live):"
for a in 172.30.0.1 172.17.0.1 185.92.220.83; do printf '  curl http://%s:18080/ -> %s\n' "$a" "$(curl -s -m 3 http://$a:18080/control || echo FAILED)"; done
echo "### neighbour sandbox (a second container on ld-sandbox serving a canary):"
NB=$(docker run -d --rm --network ld-sandbox --read-only --tmpfs /tmp:rw,size=8m --cap-drop ALL --user pwuser --label link-detonator=1 --label link-detonator.owner=nettest $IMG sh -c 'cd /tmp && echo LD-NEIGHBOUR-CANARY >index.html && exec python -m http.server 8080')
sleep 2; NBIP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$NB")
echo "  neighbour $NB at $NBIP:8080; host reaches it: $(curl -s -m 3 http://$NBIP:8080/ || echo FAILED)"
echo "### outside-in window: 20 s for an external check of 185.92.220.83:18080"; sleep 20
echo "--- sandbox phase starts" >>"$E/canary-listener.log"

echo; echo "### raw sockets inside the gVisor sandbox (same flags as a scan)"
docker run -i -e NBIP="$NBIP" $F $IMG python - <"$E/socket_probe.py" 2>&1 | sed 's/^/  /'

echo; echo "### browser (Chromium, own sandbox on) inside gVisor"
browse() {
  docker run $F $IMG python /worker/worker.py --url "$1" --deadline 20 --dwell 1 --chromium-sandbox >"$E/worker-out.ndjson" 2>/dev/null
  python3 "$E/summarize_worker.py" "$E/worker-out.ndjson"
}
R=https://postman-echo.com/redirect-to?url=
while read -r label url; do
  printf '  %-34s %s\n' "$label" "$(browse "$url")"
done <<URLS
gateway-canary http://172.30.0.1:18080/
docker0-canary http://172.17.0.1:18080/
public-ip-canary http://185.92.220.83:18080/
own-app-public-name https://185.92.220.83.sslip.io/healthz
gateway-caddy http://172.30.0.1/
gateway-ssh-port http://172.30.0.1:22/
neighbour-sandbox http://$NBIP:8080/
metadata http://169.254.169.254/latest/meta-data/
private-192.168 http://192.168.0.1/
private-172.16 http://172.16.0.1/
cgnat-100.64 http://100.64.0.1/
rebind-gateway http://172.30.0.1.sslip.io:18080/
rebind-public-ip http://185.92.220.83.sslip.io:18080/
rebind-metadata http://169.254.169.254.sslip.io/latest/meta-data/
redirect-gateway ${R}http%3A%2F%2F172.30.0.1%3A18080%2F
redirect-public-ip ${R}http%3A%2F%2F185.92.220.83%3A18080%2F
redirect-metadata ${R}http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F
redirect-rebind-gateway ${R}http%3A%2F%2F172.30.0.1.sslip.io%3A18080%2F
public-control-1 https://example.com/
public-control-2 https://www.wikipedia.org/
URLS

echo; echo "### canary listener log during the sandbox phase (any HIT here is a failure):"
sed -n '/--- sandbox phase starts/,$p' "$E/canary-listener.log" | tail -n +2 | sed 's/^/  /'
echo "  hits from the sandbox: $(sed -n '/--- sandbox phase starts/,$p' "$E/canary-listener.log" | grep -c HIT)"
in1=$(iptables -L LD-SANDBOX-INPUT -v -x -n | awk 'NR==3{print $1}')
echo "### LD-SANDBOX-INPUT REJECT packets: $in0 -> $in1"
echo "### LD-SANDBOX-EGRESS chain counters after:"; counters LD-SANDBOX-EGRESS | sed 's/^/  /'

kill "$LPID"; wait "$LPID" 2>/dev/null; docker kill "$NB" >/dev/null 2>&1
for _ in $(seq 30); do [ "$(docker ps -aq --filter label=link-detonator=1 | wc -l)" = 0 ] && break; sleep 1; done
echo "### listener stopped; port 18080 listening: $(ss -ltn | grep -c 18080)"
rules >"$E/iptables-after.txt"
if diff -q "$E/iptables-before.txt" "$E/iptables-after.txt" >/dev/null; then echo "### firewall after: identical rules ($(rules | sha256sum | cut -c1-16))"; else echo "### FIREWALL CHANGED"; diff "$E/iptables-before.txt" "$E/iptables-after.txt"; fi
echo "### containers left: $(docker ps -aq --filter label=link-detonator=1 | wc -l)"
