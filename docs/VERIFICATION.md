# Sandbox verification evidence

`deploy/verify_sandbox.sh` runs on the live VM and starts real containers with the exact flags the app uses. It makes real network attempts from inside them and prints PASS or FAIL per check. It is not a unit test: nothing is mocked.

## How a "blocked" check is judged

A failed connection alone is not proof, since nothing might be listening there. Each blocked-destination check therefore also requires the matching firewall rule's **packet counter to rise** ("firewall rule hit" lines). The browser checks run the real worker against the real firewall and record the error Chromium sees.

## What this proves, and what it does not

- **Proves**, on this VM at this time: the egress firewall blocks metadata, private, CGNAT and host addresses; the container is read-only, non-root, capability-free and limited in memory, processes and connections; secrets in the orchestrator's environment are absent from the container; a killed sandbox stops and is removed.
- **Also proves:** the QR and email decoders run with no network under gVisor (`runsc`), which gives them their own user-space kernel ("decoder runs under gVisor").
- **Does not prove:** resistance to a Chromium or Linux kernel exploit in the browser sandbox. That container still uses the standard runtime and shares the host kernel, and Chromium runs with `--no-sandbox` inside it. gVisor for the browser is not enabled: its DNS path did not work under gVisor's network stack, so it was left out rather than weakened. See the README's "Security model".
- **Runs on:** the one VM below. Re-run it after any change to Docker, the kernel or the firewall.

## Latest run (raw output, 2026-11-07, decoders under gVisor)

```
Image: link-detonator-worker:latest
Runtime: default
Decoder runtime: runsc
Public IP: 185.92.220.83

PASS  firewall rules present    firewall.sh --check
PASS  metadata blocked          169.254.169.254:80 -> EHOSTUNREACH
PASS  RFC1918 blocked           10.0.0.1:80 -> EHOSTUNREACH
PASS  RFC1918 blocked           172.16.0.1:80 -> EHOSTUNREACH
PASS  RFC1918 blocked           192.168.0.1:80 -> EHOSTUNREACH
PASS  CGNAT blocked             100.64.0.1:80 -> EHOSTUNREACH
PASS  host gateway blocked      172.30.0.1:22 -> EHOSTUNREACH
PASS  host gateway blocked      172.30.0.1:80 -> EHOSTUNREACH
PASS  host gateway blocked      172.30.0.1:443 -> EHOSTUNREACH
PASS  host gateway blocked      172.30.0.1:8000 -> EHOSTUNREACH
PASS  public-IP blocked         185.92.220.83:22 -> EHOSTUNREACH
PASS  public-IP blocked         185.92.220.83:80 -> EHOSTUNREACH
PASS  public-IP blocked         185.92.220.83:443 -> EHOSTUNREACH
PASS  public-IP blocked         185.92.220.83:8000 -> EHOSTUNREACH
PASS  other ports blocked       1.1.1.1:22 -> EHOSTUNREACH
PASS  unpinned DNS blocked      9.9.9.9:53 -> TimeoutError
PASS  IPv6 egress blocked       ENETUNREACH
PASS  DNS works                 example.com -> 2 address(es)
PASS  public HTTPS allowed      example.com: HTTP/1.1 200 OK
PASS  connection cap per destination  attempt 33 -> EHOSTUNREACH
PASS  firewall rule hit         metadata: 3 -> 4 packets
PASS  firewall rule hit         RFC1918 10/8: 3 -> 4 packets
PASS  firewall rule hit         RFC1918 172.16/12: 2 -> 3 packets
PASS  firewall rule hit         RFC1918 192.168/16: 2 -> 3 packets
PASS  firewall rule hit         CGNAT: 1 -> 2 packets
PASS  firewall rule hit         other ports: 4 -> 7 packets
PASS  firewall rule hit         host and public IP: 15 -> 30 packets
PASS  browser sees the firewall error  errors for private targets: net::ERR_ADDRESS_UNREACHABLE x6
PASS  no private answers        0 answer(s) from past the firewall
PASS  live page loads           navigation statuses: [200]
PASS  rootfs read-only          mounted ro=True, write -> EROFS
PASS  /tmp noexec               exec -> refused
PASS  no capabilities           CapBnd=0000000000000000 CapEff=0000000000000000 NoNewPrivs=True
PASS  non-root                  uid=1001 gid=1001
PASS  no env secrets            secret-like variable names: none
PASS  pid limit                 pids.max=256, refused after 254 forks
PASS  memory limit              memory.max=1073741824, allocator killed=True after 992 MiB
PASS  no env secrets            Config.Env holds none of 4 compared value(s)
PASS  no mounts                 container has 0 mounts
PASS  docker kill stops the sandbox  not running 100 ms after docker kill
PASS  decoder has no network    connect -> OSError:101, uid=1001
PASS  decoder runs under gVisor  kernel seen inside: 4.19.0-gvisor

42 passed, 0 failed
```
