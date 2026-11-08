# Sandbox verification evidence

`deploy/verify_sandbox.sh` runs on the live VM and starts real containers with the exact flags the app uses. It makes real network attempts from inside them and prints PASS or FAIL per check. It is not a unit test: nothing is mocked.

## How a "blocked" check is judged

A failed connection alone is not proof, since nothing might be listening there. Each blocked-destination check therefore also requires the matching firewall rule's **packet counter to rise** ("firewall rule hit" lines). The browser checks run the real worker against the real firewall and record the error Chromium sees.

## What this proves, and what it does not

- **Proves**, on this VM at this time: the egress firewall blocks metadata, private, CGNAT and host addresses; the container is read-only, non-root, capability-free and limited in memory, processes and connections; secrets in the orchestrator's environment are absent from the container; a killed sandbox stops and is removed.
- **Also proves:** the browser runs under gVisor ("browser runs under gVisor": the kernel seen inside is gVisor's), and Chromium's own sandbox is active in every page renderer ("chromium sandbox active": seccomp mode 2 and a single-uid user namespace, read from `/proc` inside the sandbox). The QR and email decoders run with no network under gVisor too ("decoder runs under gVisor").
- **Under gVisor, limits end the whole sandbox.** gVisor enforces the PID and memory limits by stopping the entire container rather than failing one call, so the in-container probes cannot report back. The checks instead judge host-side facts: the PID check passes only if the container exits non-zero before 256 processes and never prints that a fork succeeded past the limit; the memory check passes only if Docker records `OOMKilled`, the container reached no more than 1024 MiB, and `HostConfig.Memory` is exactly 1 GiB.
- **Does not prove:** resistance to an exploit chain. gVisor and Chromium's sandbox are shown to be in place, not to be unbreakable: a Chromium sandbox escape followed by a gVisor escape, or a bug in Docker or runsc, would still reach the VM. See the README's "Security model".
- **Network boundary under gVisor, tested separately** with a live canary listener on the host and a live neighbour sandbox, plus DNS rebinding and redirects: see [evidence/browser-gvisor/](evidence/browser-gvisor/) and the summary below.
- **Runs on:** the one VM below. Re-run it after any change to Docker, the kernel or the firewall.

## Latest run (raw output, 2026-11-08, browser and decoders under gVisor)

Run on this VM with the release image `link-detonator-worker:gvisor-bfff013` and the release settings (`LD_RUNTIME=runsc`, `LD_DECODER_RUNTIME=runsc`, `LD_SANDBOX_RESOLV_CONF`, `LD_CHROMIUM_SANDBOX=1`), before the switch-over. It is re-run after deployment.

```
Image: link-detonator-worker:gvisor-bfff013
Runtime: runsc
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
PASS  firewall rule hit         metadata: 34 -> 35 packets
PASS  firewall rule hit         RFC1918 10/8: 27 -> 28 packets
PASS  firewall rule hit         RFC1918 172.16/12: 16 -> 17 packets
PASS  firewall rule hit         RFC1918 192.168/16: 12 -> 13 packets
PASS  firewall rule hit         CGNAT: 9 -> 10 packets
PASS  firewall rule hit         other ports: 111 -> 114 packets
PASS  firewall rule hit         host and public IP: 91 -> 106 packets
PASS  browser sees the firewall error  errors for private targets: net::ERR_ADDRESS_UNREACHABLE x6
PASS  no private answers        0 answer(s) from past the firewall
PASS  live page loads           navigation statuses: [200]
PASS  rootfs read-only          mounted ro=True, write -> EROFS
PASS  /tmp noexec               exec -> refused
PASS  no capabilities           CapBnd=0000000000000000 CapEff=0000000000000000 NoNewPrivs=True
PASS  non-root                  uid=1001 gid=1001
PASS  no env secrets            secret-like variable names: none
PASS  browser runs under gVisor  kernel seen inside: 4.19.0-gvisor
PASS  pid limit                 gVisor sandbox ended after 111 guest processes (pids-limit 256, exit 2)
PASS  memory limit              gVisor sandbox OOM-killed by the host after 992 MiB (memory limit 1073741824, exit 137)
PASS  chromium sandbox active   page renderers (seccomp, uid range): [('2', '1')]
PASS  no env secrets            Config.Env holds none of 4 compared value(s)
PASS  no mounts                 only the read-only resolver file (/etc/link-detonator/sandbox-resolv.conf>/etc/resolv.conf>false;)
PASS  docker kill stops the sandbox  not running 100 ms after docker kill
PASS  decoder has no network    connect -> OSError:101, uid=1001
PASS  decoder runs under gVisor  kernel seen inside: 4.19.0-gvisor

44 passed, 0 failed
```

The run of 2026-11-07, with the browser on the standard runtime, passed 42 of 42; it is in the git history of this file.

## Network boundary under gVisor (2026-11-08)

The checks above use addresses where nothing may be listening, so a refusal alone could be a closed port. This separate test puts real services behind the targets. Raw output: [evidence/browser-gvisor/network-boundary.txt](evidence/browser-gvisor/network-boundary.txt), scripts in [evidence/browser-gvisor/scripts/](evidence/browser-gvisor/scripts/).

- **Live targets.** A canary HTTP listener on the host, bound to the sandbox gateway `172.30.0.1`, `docker0` (`172.17.0.1`) and the public IP (not `0.0.0.0`), answered the host itself on all three. A second container on the sandbox network served its own canary, confirmed from inside it.
- **From the gVisor sandbox, all refused.** Raw sockets: "No route to host" for the three canaries, sshd, Caddy, the app port, the neighbour sandbox, metadata, 10/8, 172.16/12, 192.168/16, 100.64/10 and DNS-over-TLS; unauthorized resolvers (9.9.9.9, 8.8.4.4, 208.67.222.222, the gateway, 127.0.0.11) timed out over UDP and were refused over TCP; IPv6 metadata unreachable. Chromium, with its own sandbox on: `ERR_ADDRESS_UNREACHABLE` for every host, private and metadata target, by address, by DNS-rebinding name (`*.sslip.io`) and through public 302 redirects to each (port 22 is refused by Chromium itself as `ERR_UNSAFE_PORT`).
- **Proof it was the firewall.** The canary logged 0 hits from the sandbox, and the `LD-SANDBOX-INPUT` reject counter rose (64 to 91) along with the egress reject counters.
- **Public access kept.** The pinned resolvers answered, `1.1.1.1:443` connected, and `example.com` and `www.wikipedia.org` loaded with HTTP 200.
- **The test weakened nothing.** No rule was added: `iptables-save` was identical before and after (counters ignored). From outside the VM, the canary port timed out while it was listening, so ufw kept it closed. Listener stopped, 0 containers left.

## End-to-end scans and teardown (2026-11-08)

Through the app's API with the release image: [evidence/browser-gvisor/e2e-bfff013.txt](evidence/browser-gvisor/e2e-bfff013.txt). Successful scans (Gauntlet, phishing, download, SSRF, benign) and failing ones (a frozen page, an out-of-memory page killed by the host with exit 137, and two scans stopped early by a 4.5 s worker deadline). After every one: removal verified by the host, 0 labelled containers, 0 `runsc-sandbox` and 0 `runsc-gofer` processes. Every receipt passed `tools/verify_receipt.py` with the saved digest and the downloaded screenshots, and failed after a one-field edit.

## Rollback

The previous production image is kept as `link-detonator-worker:prod-6a3fcec` (image ID `sha256:ae0a280682e49ba002a680db8300438ecf0ac65ee1a382bc8c1eecf3daf35fc6`), built from commit `6a3fcec`. To return to the standard runtime:

1. Remove `LD_RUNTIME`, `LD_SANDBOX_RESOLV_CONF` and `LD_CHROMIUM_SANDBOX` from `/etc/link-detonator/app.env` (keep `LD_DECODER_RUNTIME=runsc`, which predates this change), or set `LD_CHROMIUM_SANDBOX=0` and `LD_RUNTIME=`.
2. `docker tag link-detonator-worker:prod-6a3fcec link-detonator-worker:latest`
3. Restore the code of commit `6a3fcec`: the deploy keeps a copy of the previous tree at `/opt/link-detonator.prod-6a3fcec`, so `rsync -a --delete --exclude=.venv --exclude=data /opt/link-detonator.prod-6a3fcec/ /opt/link-detonator/` (or `git archive 6a3fcec | tar -x -C /opt/link-detonator`), then `systemctl restart link-detonator`.
4. Run `deploy/verify_sandbox.sh`; it should report 42 of 42 with "Runtime: default".

Step 1 alone, with a restart, already returns the browser to runc: the new code with default settings builds exactly the earlier argv. Steps 2 and 3 return the code as well.
