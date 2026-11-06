# Architecture

This explains how the parts fit together and why. [CONTRACT.md](CONTRACT.md) holds the exact rules, and the code must conform to it. The sandbox and firewall described here are verified on the live VM: see [VERIFICATION.md](VERIFICATION.md) for the raw output and its limits.

## Components

| Part | Where it runs | Trust |
|---|---|---|
| Caddy | VM | Terminates HTTPS, proxies to `127.0.0.1:8000` |
| FastAPI orchestrator (`app/`) | VM, as user `detonator` | Trusted. Assigns all event sequence numbers and timestamps |
| Worker (`worker/`) | Sandbox container | **Hostile once a page has loaded.** Its output is untrusted input |
| Firewall (`deploy/firewall.sh`) | VM kernel | The real network boundary |
| Agent (`app/agent/`) | VM, inside the orchestrator | Proposes only. A deterministic policy decides; model output is treated as untrusted |

## A scan, step by step

1. `POST /api/scans` validates the URL (`urlpolicy.py`). This is a courtesy and defence in depth. DNS rebinding and redirects can get around it, so the firewall is what actually enforces the policy.
2. The job waits in a queue, limited by concurrency and per-client rate limits.
3. `DockerRunner` starts a container from an argv list, never a shell.
4. The worker visits the page without clicking, typing or submitting, and writes JSON lines to stdout.
5. The host validates and caps each line, and adds its own `seq`, `source` and `ts`. Exceeding a hard cap kills the container.
6. The deadline triggers `docker kill`. `docker rm -f` always runs, followed by `docker inspect` to confirm the container is gone.
7. `blast_radius.py` turns events into report rows, and a row says `contained` only when events prove it.

## Isolation layers

```
Page JavaScript
  Chromium renderer (--no-sandbox: its own sandbox is off)
    Container: read-only rootfs, noexec /tmp, no capabilities, non-root,
               no-new-privileges, CPU/memory/PID limits, no mounts, no env
      Firewall: INPUT and DOCKER-USER rules on ld-br0
        VM: disposable, holds nothing else
```

A browser exploit lands in the container. A kernel exploit lands on the VM, which is why the VM must be disposable.

## Network policy

`DOCKER-USER` only sees forwarded traffic. A packet from a container to the VM, including to the VM's public IP, is local delivery and goes through `INPUT` instead. Both paths therefore need rules.

```
from ld-br0, to the VM itself:     INPUT -> LD-SANDBOX-INPUT       -> blocked
from ld-br0, to anywhere else:     FORWARD -> DOCKER-USER -> LD-SANDBOX-EGRESS
    established                                       continue
    169.254/16 10/8 172.16/12 192.168/16 100.64/10
    127/8 0/8 224/4 240/4                             blocked
    UDP or TCP 53 to the 2 pinned resolvers           continue
    TCP 80, TCP 443                                   continue
    everything else                                   blocked
```

"Continue" means `RETURN`, which hands the packet back to Docker's own rules rather than accepting it outright. Those rules still apply, including the inter-container block.

### Firewall decisions

The first two changed CONTRACT.md's network section, which records why. Neither has run on a VM yet.

**1. Blocked traffic is REJECTed, not silently dropped.**
With a silent drop, Chromium keeps retrying the connection. On Linux defaults that takes about two minutes, well past the 60-second deadline. `request_failed` would never fire, so the `private_network` row could never reach `contained`, which requires a failed request. A hanging `<img>` would also hold up the page's `load` event. A reject (`icmp-admin-prohibited`) fails at once. The packet is stopped either way, and all a page learns is that a firewall exists, which it could also infer from a timeout. The timing is reasoning from defaults and has not been measured. To return to a literal drop, change `BLOCK_TARGET` in `firewall.sh`.

**2. DNS is allowed to two pinned resolvers.**
The contract allows TCP 80/443 and drops everything else, yet also requires "DNS works". Those conflict. Docker's embedded resolver dials non-loopback upstream servers from inside the container's network namespace (`dialExtDNS` in moby's `resolver.go`, and the `--dns` documentation). Those queries pass through `DOCKER-USER`, where the contract's rules would drop them. So `provision.sh` pins resolvers in `/etc/docker/daemon.json`, and the firewall allows port 53 to those addresses only. They are `1.1.1.1` and `8.8.8.8`, chosen because a resolver that filters known-bad domains would hide what a scan is meant to see.

**3. Rules live in their own chains.** `iptables-restore --noflush` replaces each chain in one transaction, so a re-run never leaves it empty or partial.

**4. Rules are loaded before the network is created.** They match the bridge by name, so `ld-br0` never exists without them.

**5. Rule order is enforced against ufw.** Vultr images often enable ufw, whose rules allow 22, 80 and 443 in `INPUT`. Our jump must come first, or a container could reach those services. ufw also accepts ICMP echo in its forward chains, so `DOCKER-USER` must come first in `FORWARD`. `firewall.sh` enforces both, and `--check` fails if either is wrong.

**6. IPv6 is blocked as well as off.** The network has IPv6 disabled, and `ip6tables` rules cover any link-local path to the host anyway.

**7. Egress is throttled.** A scanned page can POST or flood from this VM's address, so the chain caps upload bytes per sandbox address, connections per destination and new connections per destination per second. Private destinations are rejected before these rules, so they always get the plain rejection. The numbers are estimates and have not been measured against real pages.

## What `private_network` trusts

The row reads `contained` only for `net::ERR_ADDRESS_UNREACHABLE`, the error `icmp-admin-prohibited` should become in Chromium. A test on a Mac, loopback only, showed why nothing looser works: from an `http` page, Chromium's own local-network check opened the TCP connection and then failed the request with `net::ERR_FAILED`, with no firewall involved. The worker now turns that check off, which that same test confirmed let requests reach a listener. Neither the REJECT error string nor any of this on Linux has been measured: `verify_sandbox.sh` runs the real worker on `hostile-ssrf` in the sandbox and fails if any other error comes back. If it does, fix the cause or change the list in `app/blast_radius.py` and `deploy/check_worker_events.py` together.

## Failure behaviour

The design fails closed:

- `link-detonator.service` is bound to the firewall unit, and runs `firewall.sh --check` before starting. No policy means no app.
- The firewall unit has no stop action, so stopping it never opens anything.
- When Docker restarts, the firewall unit re-runs. The app restarts with it, so running scans become `interrupted`.
- `provision.sh` starts the app only after `verify_sandbox.sh` passes, and disables it first so that a failed run cannot return at the next boot.

## How verification avoids false passes

- A failed connection could just mean nothing was listening, so blocked checks also require the matching rule's packet counter to rise.
- Every required check must report a result. A probe that crashes or goes quiet counts as a FAIL.
- The worker itself runs under the exact flags: its real error strings are checked against what the report trusts, and a live page must load through the route that stops non-GET requests.
- The secret check plants a random canary in the Docker client's environment and looks for it in `Config.Env`, so it does real work on a VM with no secrets configured yet. Values are compared in-process and never printed.

The counters are why it should run with no scans in progress: another scan's traffic could raise them.

## Known tradeoff: the docker group

`detonator` is in the `docker` group, which is root-equivalent on the VM. A compromise of the orchestrator is effectively root. The systemd hardening in the unit limits accidents, not an attacker. A narrower Docker API proxy would help, but was not worth the added moving parts for a disposable, single-purpose VM. That is why **this VM must hold nothing else**.

## The agent

`app/agent/` replaced `PendingVerdictEngine` after kickoff. The model reads recorded evidence, which is attacker-controlled and passed only as data inside a marked block, and proposes a verdict and follow-up actions. `policy.py` allows one action kind, opening a link seen in the evidence, and only in a fresh sandbox. `verify.py` reports outcomes from host-recorded facts and never from the model's claims. Three checks run without trusting the model: a planted secret, a with-and-without-hidden-text comparison, and hidden-text pattern detectors. They can raise the verdict, never lower it. Measured results are in [reports/README.md](../reports/README.md).
